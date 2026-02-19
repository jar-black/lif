"""MCP Deals Service – Grocery deal scraper with FastMCP on port 8003."""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from jose import JWTError, jwt
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from sqlmodel import Field, Session, SQLModel, create_engine, select
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database model
# ---------------------------------------------------------------------------


class Deal(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    store_name: str
    store_address: Optional[str] = None
    product_name: str
    description: Optional[str] = None
    original_price: Optional[float] = None
    deal_price: Optional[float] = None
    discount_pct: Optional[float] = None
    category: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    image_url: Optional[str] = None
    scraped_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------

DB_PATH = os.getenv("DB_PATH", "/data/deals.db")
engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)


def create_db():
    SQLModel.metadata.create_all(engine)


# Ensure DB schema exists on import (synchronous, idempotent)
create_db()


# ---------------------------------------------------------------------------
# JWT Auth config
# ---------------------------------------------------------------------------

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# ---------------------------------------------------------------------------
# Scraper runner (imported after Deal model is defined)
# ---------------------------------------------------------------------------

from scraper import ScraperRunner, background_refresh_task  # noqa: E402

runner = ScraperRunner(engine)

# ---------------------------------------------------------------------------
# FastMCP setup
# ---------------------------------------------------------------------------


@asynccontextmanager
async def app_lifespan(app):
    create_db()
    task = asyncio.create_task(background_refresh_task(runner))
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# DNS rebinding protection is disabled: this service runs behind Traefik (trusted network)
_security = TransportSecuritySettings(allowed_hosts=["localhost"])
mcp = FastMCP("Deals", stateless_http=True, transport_security=_security)

# ---------------------------------------------------------------------------
# JWT auth middleware (raw ASGI — safe for SSE streaming)
# ---------------------------------------------------------------------------


class JWTAuthMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            response = Response(status_code=401)
            await response(scope, receive, send)
            return

        token = auth_header[7:]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except JWTError:
            response = Response(status_code=401)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def get_all_deals(category: Optional[str] = None) -> list[dict]:
    """Get all cached grocery deals, optionally filtered by category."""
    with Session(engine) as session:
        stmt = select(Deal)
        if category:
            stmt = stmt.where(Deal.category == category)
        deals = session.exec(stmt).all()
        return [_deal_to_dict(d) for d in deals]


@mcp.tool()
def get_store_deals(store_name: str) -> list[dict]:
    """Get deals from a specific store (e.g. Hemkop, Willys, Lidl)."""
    with Session(engine) as session:
        deals = session.exec(
            select(Deal).where(Deal.store_name == store_name)
        ).all()
        return [_deal_to_dict(d) for d in deals]


@mcp.tool()
def search_deals(query: str) -> list[dict]:
    """Search deals by product name or description (case-insensitive)."""
    with Session(engine) as session:
        pattern = f"%{query}%"
        deals = session.exec(
            select(Deal).where(
                (Deal.product_name.ilike(pattern))  # type: ignore[union-attr]
                | (Deal.description.ilike(pattern))  # type: ignore[union-attr]
            )
        ).all()
        return [_deal_to_dict(d) for d in deals]


@mcp.tool()
def get_deal_categories() -> list[str]:
    """Get all distinct deal categories across all stores."""
    with Session(engine) as session:
        results = session.exec(
            select(Deal.category).distinct().where(Deal.category.isnot(None))  # type: ignore[union-attr]
        ).all()
        return sorted([c for c in results if c])


@mcp.tool()
async def refresh_deals() -> dict:
    """Manually trigger a deal refresh. Rate limited to once per hour."""
    result = await runner.manual_refresh()
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _deal_to_dict(deal: Deal) -> dict:
    return {
        "id": deal.id,
        "store_name": deal.store_name,
        "store_address": deal.store_address,
        "product_name": deal.product_name,
        "description": deal.description,
        "original_price": deal.original_price,
        "deal_price": deal.deal_price,
        "discount_pct": deal.discount_pct,
        "category": deal.category,
        "valid_from": deal.valid_from.isoformat() if deal.valid_from else None,
        "valid_to": deal.valid_to.isoformat() if deal.valid_to else None,
        "image_url": deal.image_url,
        "scraped_at": deal.scraped_at.isoformat() if deal.scraped_at else None,
    }


# ---------------------------------------------------------------------------
# ASGI app
# ---------------------------------------------------------------------------


async def _lifespan(scope, receive, send):
    pass  # handled below via startup hook in the Starlette app


_mcp_inner = mcp.streamable_http_app()

# Wrap the MCP Starlette app's startup to initialise DB + background task.
# We do this by subclassing to hook into the lifespan.
from starlette.applications import Starlette  # noqa: E402


async def startup():
    create_db()
    asyncio.create_task(background_refresh_task(runner))


_mcp_inner.router.on_startup.append(startup)

app = JWTAuthMiddleware(_mcp_inner)
