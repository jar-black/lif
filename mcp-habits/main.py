import json
import os
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from sqlmodel import Session, SQLModel, create_engine, select
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from models import Category, FrequencyPeriod, Habit, HabitLog

# --- Database setup ---

DATABASE_URL = "sqlite:////data/habits.db"
engine = create_engine(DATABASE_URL, echo=False)

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"

DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def init_db():
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        count = session.exec(select(Habit)).first()
        if count is None:
            seed_habits(session)


def seed_habits(session: Session):
    habits = [
        Habit(
            name="Guitar practice",
            frequency_count=3,
            frequency_period=FrequencyPeriod.weekly,
            category=Category.hobby,
            preferred_days=json.dumps(["Mon", "Wed", "Fri"]),
        ),
        Habit(
            name="Call mother",
            frequency_count=2,
            frequency_period=FrequencyPeriod.weekly,
            category=Category.social,
        ),
        Habit(
            name="Outing with kids",
            frequency_count=1,
            frequency_period=FrequencyPeriod.weekly,
            category=Category.family,
            notes="Kids are 13 and 16",
        ),
    ]
    for habit in habits:
        session.add(habit)
    session.commit()


# --- MCP server ---

# DNS rebinding protection is disabled: this service runs behind Traefik (trusted network)
_security = TransportSecuritySettings(allowed_hosts=["localhost"])
mcp = FastMCP("mcp-habits", stateless_http=True, transport_security=_security)


# --- JWT auth middleware (raw ASGI — safe for SSE streaming) ---


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


# --- Helper functions ---


def get_week_start(dt: Optional[datetime] = None) -> datetime:
    """Get Monday 00:00 of the current week."""
    if dt is None:
        dt = datetime.utcnow()
    monday = dt - timedelta(days=dt.weekday())
    return monday.replace(hour=0, minute=0, second=0, microsecond=0)


def get_week_end(week_start: datetime) -> datetime:
    """Get Sunday 23:59:59 of the week."""
    return week_start + timedelta(days=6, hours=23, minutes=59, seconds=59)


def count_logs_this_week(session: Session, habit_id: int) -> int:
    week_start = get_week_start()
    week_end = get_week_end(week_start)
    logs = session.exec(
        select(HabitLog).where(
            HabitLog.habit_id == habit_id,
            HabitLog.completed_at >= week_start,
            HabitLog.completed_at <= week_end,
        )
    ).all()
    return len(logs)


# --- Tools ---


@mcp.tool()
def list_habits(active_only: bool = True) -> list[dict]:
    """List all habits with this-week completion count."""
    with Session(engine) as session:
        stmt = select(Habit)
        if active_only:
            stmt = stmt.where(Habit.active == True)
        habits = session.exec(stmt).all()
        result = []
        for h in habits:
            completions = count_logs_this_week(session, h.id)
            result.append({
                "id": h.id,
                "name": h.name,
                "description": h.description,
                "category": h.category.value,
                "frequency_count": h.frequency_count,
                "frequency_period": h.frequency_period.value,
                "preferred_days": json.loads(h.preferred_days) if h.preferred_days else None,
                "notes": h.notes,
                "active": h.active,
                "completions_this_week": completions,
                "created_at": h.created_at.isoformat(),
            })
        return result


@mcp.tool()
def add_habit(
    name: str,
    description: Optional[str] = None,
    category: str = "other",
    frequency_count: int = 1,
    frequency_period: str = "weekly",
    preferred_days: Optional[list[str]] = None,
) -> dict:
    """Create a new habit."""
    with Session(engine) as session:
        habit = Habit(
            name=name,
            description=description,
            category=Category(category),
            frequency_count=frequency_count,
            frequency_period=FrequencyPeriod(frequency_period),
            preferred_days=json.dumps(preferred_days) if preferred_days else None,
        )
        session.add(habit)
        session.commit()
        session.refresh(habit)
        return {"id": habit.id, "name": habit.name, "status": "created"}


@mcp.tool()
def update_habit(
    habit_id: int,
    name: Optional[str] = None,
    description: Optional[str] = None,
    category: Optional[str] = None,
    frequency_count: Optional[int] = None,
    frequency_period: Optional[str] = None,
    preferred_days: Optional[list[str]] = None,
    notes: Optional[str] = None,
) -> dict:
    """Update provided fields of a habit."""
    with Session(engine) as session:
        habit = session.get(Habit, habit_id)
        if not habit:
            return {"error": f"Habit {habit_id} not found"}
        if name is not None:
            habit.name = name
        if description is not None:
            habit.description = description
        if category is not None:
            habit.category = Category(category)
        if frequency_count is not None:
            habit.frequency_count = frequency_count
        if frequency_period is not None:
            habit.frequency_period = FrequencyPeriod(frequency_period)
        if preferred_days is not None:
            habit.preferred_days = json.dumps(preferred_days)
        if notes is not None:
            habit.notes = notes
        session.add(habit)
        session.commit()
        session.refresh(habit)
        return {"id": habit.id, "name": habit.name, "status": "updated"}


@mcp.tool()
def delete_habit(habit_id: int) -> dict:
    """Soft delete a habit by setting active=False."""
    with Session(engine) as session:
        habit = session.get(Habit, habit_id)
        if not habit:
            return {"error": f"Habit {habit_id} not found"}
        habit.active = False
        session.add(habit)
        session.commit()
        return {"id": habit.id, "name": habit.name, "status": "deleted"}


@mcp.tool()
def log_completion(
    habit_id: int,
    notes: Optional[str] = None,
    duration_minutes: Optional[int] = None,
    completed_at: Optional[str] = None,
) -> dict:
    """Log a habit completion. completed_at defaults to now (ISO format if provided)."""
    with Session(engine) as session:
        habit = session.get(Habit, habit_id)
        if not habit:
            return {"error": f"Habit {habit_id} not found"}

        ts = datetime.fromisoformat(completed_at) if completed_at else datetime.utcnow()
        log = HabitLog(
            habit_id=habit_id,
            notes=notes,
            duration_minutes=duration_minutes,
            completed_at=ts,
        )
        session.add(log)
        session.commit()
        session.refresh(log)
        return {
            "id": log.id,
            "habit_id": habit_id,
            "habit_name": habit.name,
            "completed_at": log.completed_at.isoformat(),
            "status": "logged",
        }


@mcp.tool()
def get_habit_progress(habit_id: int, weeks: int = 4) -> dict:
    """Get last N weeks of logs grouped by week, with completion rate."""
    with Session(engine) as session:
        habit = session.get(Habit, habit_id)
        if not habit:
            return {"error": f"Habit {habit_id} not found"}

        now = datetime.utcnow()
        start = get_week_start(now) - timedelta(weeks=weeks - 1)

        logs = session.exec(
            select(HabitLog)
            .where(HabitLog.habit_id == habit_id, HabitLog.completed_at >= start)
            .order_by(HabitLog.completed_at)
        ).all()

        weekly: dict[str, list] = {}
        for i in range(weeks):
            ws = start + timedelta(weeks=i)
            key = ws.strftime("%Y-%m-%d")
            weekly[key] = []

        for log in logs:
            ws = get_week_start(log.completed_at)
            key = ws.strftime("%Y-%m-%d")
            if key in weekly:
                weekly[key].append({
                    "completed_at": log.completed_at.isoformat(),
                    "notes": log.notes,
                    "duration_minutes": log.duration_minutes,
                })

        target = habit.frequency_count
        week_summaries = []
        for week_key in sorted(weekly.keys()):
            count = len(weekly[week_key])
            week_summaries.append({
                "week_start": week_key,
                "completions": count,
                "target": target,
                "rate": round(count / target, 2) if target > 0 else 0,
                "logs": weekly[week_key],
            })

        return {
            "habit_id": habit.id,
            "habit_name": habit.name,
            "frequency": f"{habit.frequency_count}x/{habit.frequency_period.value}",
            "weeks": week_summaries,
        }


@mcp.tool()
def get_weekly_summary() -> list[dict]:
    """All active habits with target frequency, completions this week, remaining needed, next preferred day."""
    with Session(engine) as session:
        habits = session.exec(select(Habit).where(Habit.active == True)).all()
        now = datetime.utcnow()
        today_index = now.weekday()  # 0=Mon

        result = []
        for h in habits:
            completions = count_logs_this_week(session, h.id)
            remaining = max(0, h.frequency_count - completions)

            preferred = json.loads(h.preferred_days) if h.preferred_days else []
            next_preferred = None
            if preferred:
                for offset in range(1, 8):
                    day_idx = (today_index + offset) % 7
                    if DAY_NAMES[day_idx] in preferred:
                        next_preferred = DAY_NAMES[day_idx]
                        break

            result.append({
                "habit_id": h.id,
                "name": h.name,
                "category": h.category.value,
                "target": h.frequency_count,
                "frequency_period": h.frequency_period.value,
                "completions_this_week": completions,
                "remaining": remaining,
                "next_preferred_day": next_preferred,
            })
        return result


@mcp.tool()
def suggest_schedule(habit_id: int) -> dict:
    """Analyze log history to find which days habit is most often completed, suggest best upcoming day(s)."""
    with Session(engine) as session:
        habit = session.get(Habit, habit_id)
        if not habit:
            return {"error": f"Habit {habit_id} not found"}

        logs = session.exec(
            select(HabitLog).where(HabitLog.habit_id == habit_id)
        ).all()

        # Count completions by day of week
        day_counts: dict[str, int] = defaultdict(int)
        for log in logs:
            day_name = DAY_NAMES[log.completed_at.weekday()]
            day_counts[day_name] += 1

        preferred = json.loads(habit.preferred_days) if habit.preferred_days else []

        # Score each day: historical frequency + preferred day bonus
        day_scores: dict[str, float] = {}
        for day in DAY_NAMES:
            score = day_counts.get(day, 0)
            if day in preferred:
                score += 5  # bonus for preferred days
            day_scores[day] = score

        # Sort by score descending
        ranked = sorted(day_scores.items(), key=lambda x: x[1], reverse=True)

        # Suggest top N days based on frequency_count
        suggested = [d[0] for d in ranked[: habit.frequency_count]]

        # Find next upcoming suggested day
        now = datetime.utcnow()
        today_index = now.weekday()
        next_day = None
        for offset in range(1, 8):
            day_idx = (today_index + offset) % 7
            if DAY_NAMES[day_idx] in suggested:
                next_day = DAY_NAMES[day_idx]
                break

        return {
            "habit_id": habit.id,
            "habit_name": habit.name,
            "historical_pattern": dict(day_counts),
            "preferred_days": preferred,
            "suggested_days": suggested,
            "next_suggested_day": next_day,
        }


# --- App setup ---

init_db()

_inner = mcp.streamable_http_app()
app = JWTAuthMiddleware(_inner)
