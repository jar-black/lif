import os
from datetime import datetime
from typing import Optional

from jose import JWTError, jwt
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from sqlmodel import Session, SQLModel, create_engine, select, func
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from models import Item, List, ListType, Priority

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASE_URL = "sqlite:////data/lists.db"
engine = create_engine(DATABASE_URL, echo=False)
SQLModel.metadata.create_all(engine)

# ---------------------------------------------------------------------------
# FastMCP server
# ---------------------------------------------------------------------------
# DNS rebinding protection is disabled: this service runs behind Traefik (trusted network)
_security = TransportSecuritySettings(allowed_hosts=["localhost"])
mcp = FastMCP("mcp-lists", stateless_http=True, transport_security=_security)

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def create_list(
    name: str,
    type: str = "todo",
    location: Optional[str] = None,
    description: Optional[str] = None,
) -> dict:
    """Create a new list."""
    lst = List(
        name=name,
        type=ListType(type),
        location=location,
        description=description,
    )
    with Session(engine) as session:
        session.add(lst)
        session.commit()
        session.refresh(lst)
        return lst.model_dump()


@mcp.tool()
def get_lists() -> list[dict]:
    """Get all lists with item counts (completed / total)."""
    with Session(engine) as session:
        lists = session.exec(select(List)).all()
        results = []
        for lst in lists:
            total = session.exec(
                select(func.count(Item.id)).where(Item.list_id == lst.id)
            ).one()
            completed = session.exec(
                select(func.count(Item.id)).where(
                    Item.list_id == lst.id, Item.completed == True  # noqa: E712
                )
            ).one()
            d = lst.model_dump()
            d["item_count"] = total
            d["completed_count"] = completed
            results.append(d)
        return results


@mcp.tool()
def get_list(list_id: int) -> dict:
    """Get a single list with all its items."""
    with Session(engine) as session:
        lst = session.get(List, list_id)
        if not lst:
            return {"error": f"List {list_id} not found"}
        items = session.exec(
            select(Item).where(Item.list_id == list_id).order_by(Item.sort_order)
        ).all()
        d = lst.model_dump()
        d["items"] = [i.model_dump() for i in items]
        return d


@mcp.tool()
def delete_list(list_id: int) -> dict:
    """Delete a list and all its items."""
    with Session(engine) as session:
        lst = session.get(List, list_id)
        if not lst:
            return {"error": f"List {list_id} not found"}
        items = session.exec(select(Item).where(Item.list_id == list_id)).all()
        for item in items:
            session.delete(item)
        session.delete(lst)
        session.commit()
        return {"deleted": list_id}


@mcp.tool()
def add_item(
    list_id: int,
    title: str,
    description: Optional[str] = None,
    location: Optional[str] = None,
    due_date: Optional[str] = None,
    priority: str = "medium",
    category: Optional[str] = None,
) -> dict:
    """Add an item to a list."""
    with Session(engine) as session:
        lst = session.get(List, list_id)
        if not lst:
            return {"error": f"List {list_id} not found"}
        # Determine next sort_order
        max_order = session.exec(
            select(func.max(Item.sort_order)).where(Item.list_id == list_id)
        ).one()
        next_order = (max_order or 0) + 1
        item = Item(
            list_id=list_id,
            title=title,
            description=description,
            location=location,
            due_date=datetime.fromisoformat(due_date) if due_date else None,
            priority=Priority(priority),
            category=category,
            sort_order=next_order,
        )
        session.add(item)
        session.commit()
        session.refresh(item)
        return item.model_dump()


@mcp.tool()
def update_item(
    item_id: int,
    title: Optional[str] = None,
    description: Optional[str] = None,
    location: Optional[str] = None,
    due_date: Optional[str] = None,
    priority: Optional[str] = None,
    category: Optional[str] = None,
    sort_order: Optional[int] = None,
) -> dict:
    """Update fields on an item."""
    with Session(engine) as session:
        item = session.get(Item, item_id)
        if not item:
            return {"error": f"Item {item_id} not found"}
        if title is not None:
            item.title = title
        if description is not None:
            item.description = description
        if location is not None:
            item.location = location
        if due_date is not None:
            item.due_date = datetime.fromisoformat(due_date)
        if priority is not None:
            item.priority = Priority(priority)
        if category is not None:
            item.category = category
        if sort_order is not None:
            item.sort_order = sort_order
        item.updated_at = datetime.utcnow()
        session.add(item)
        session.commit()
        session.refresh(item)
        return item.model_dump()


@mcp.tool()
def complete_item(item_id: int) -> dict:
    """Mark an item as completed."""
    with Session(engine) as session:
        item = session.get(Item, item_id)
        if not item:
            return {"error": f"Item {item_id} not found"}
        item.completed = True
        item.completed_at = datetime.utcnow()
        item.updated_at = datetime.utcnow()
        session.add(item)
        session.commit()
        session.refresh(item)
        return item.model_dump()


@mcp.tool()
def delete_item(item_id: int) -> dict:
    """Delete an item."""
    with Session(engine) as session:
        item = session.get(Item, item_id)
        if not item:
            return {"error": f"Item {item_id} not found"}
        session.delete(item)
        session.commit()
        return {"deleted": item_id}


@mcp.tool()
def reorder_items(list_id: int, item_ids: list[int]) -> dict:
    """Reorder items in a list. item_ids should contain all item IDs in the desired order."""
    with Session(engine) as session:
        for idx, item_id in enumerate(item_ids):
            item = session.get(Item, item_id)
            if item and item.list_id == list_id:
                item.sort_order = idx
                session.add(item)
        session.commit()
        return {"reordered": list_id, "order": item_ids}


# ---------------------------------------------------------------------------
# JWT Auth Middleware
# ---------------------------------------------------------------------------
JWT_SECRET = os.environ["JWT_SECRET"]


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
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except JWTError:
            response = Response(status_code=401)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# ASGI app
# ---------------------------------------------------------------------------
_inner = mcp.streamable_http_app()
app = JWTAuthMiddleware(_inner)
