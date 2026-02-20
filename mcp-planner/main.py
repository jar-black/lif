import os
from datetime import date, datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from sqlmodel import Field, Session, SQLModel, create_engine, select
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

# --- Database setup ---

DATABASE_URL = "sqlite:////data/planner.db"
engine = create_engine(DATABASE_URL, echo=False)

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"


class Plan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    date: str = Field(unique=True, index=True)  # ISO format YYYY-MM-DD
    plan: str
    updated_at: datetime = Field(default_factory=datetime.utcnow)


def init_db():
    SQLModel.metadata.create_all(engine)


# --- MCP server ---

INSTRUCTIONS = """You are a day planner assistant. Help the user organize their day effectively.

When the user wants to plan their day:
1. First check if they already have a plan for today using get_plan()
2. Ask about their priorities, meetings, and tasks
3. Help them create a structured plan with time blocks
4. Store the plan using set_plan()

When showing plans, format them clearly. Use get_plans() to show a weekly overview.

Tips for good plans:
- Group similar tasks together
- Schedule deep work in the morning
- Include breaks and buffer time
- Be specific about what needs to be done"""

_security = TransportSecuritySettings(allowed_hosts=["localhost"])
mcp = FastMCP(
    "mcp-planner",
    stateless_http=True,
    transport_security=_security,
    instructions=INSTRUCTIONS,
)


# --- JWT auth middleware ---


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


# --- Tools ---


@mcp.tool()
def get_plan(date: Optional[str] = None) -> dict:
    """Get plan for a date (defaults to today).

    Args:
        date: Date in YYYY-MM-DD format (defaults to today)
    """
    target_date = date or str(date_module_today())
    with Session(engine) as session:
        plan = session.exec(
            select(Plan).where(Plan.date == target_date)
        ).first()
        if plan:
            return {
                "date": plan.date,
                "plan": plan.plan,
                "updated_at": plan.updated_at.isoformat(),
            }
        return {"date": target_date, "plan": None}


@mcp.tool()
def set_plan(plan: str, date: Optional[str] = None) -> dict:
    """Set or update the plan for a date (defaults to today).

    Args:
        plan: The plan content (free-form text)
        date: Date in YYYY-MM-DD format (defaults to today)
    """
    target_date = date or str(date_module_today())
    with Session(engine) as session:
        existing = session.exec(
            select(Plan).where(Plan.date == target_date)
        ).first()
        if existing:
            existing.plan = plan
            existing.updated_at = datetime.utcnow()
            session.add(existing)
        else:
            new_plan = Plan(date=target_date, plan=plan)
            session.add(new_plan)
        session.commit()
        return {"date": target_date, "status": "saved"}


@mcp.tool()
def get_plans(days: int = 7) -> list[dict]:
    """Get plans for the next N days (for weekly overview).

    Args:
        days: Number of days to look ahead (default: 7)
    """
    today = date_module_today()
    dates = [str(today + timedelta(days=i)) for i in range(days)]

    with Session(engine) as session:
        plans = session.exec(
            select(Plan).where(Plan.date.in_(dates))
        ).all()
        plan_map = {p.date: p for p in plans}

        result = []
        for d in dates:
            if d in plan_map:
                p = plan_map[d]
                result.append({
                    "date": p.date,
                    "plan": p.plan,
                    "updated_at": p.updated_at.isoformat(),
                })
            else:
                result.append({"date": d, "plan": None})
        return result


def date_module_today() -> date:
    """Get today's date. Separated for testability."""
    return date.today()


# --- App setup ---

init_db()

_inner = mcp.streamable_http_app()
app = JWTAuthMiddleware(_inner)
