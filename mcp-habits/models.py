from datetime import datetime
from enum import Enum
from typing import Optional

from sqlmodel import Field, SQLModel


class Category(str, Enum):
    fitness = "fitness"
    social = "social"
    family = "family"
    health = "health"
    hobby = "hobby"
    other = "other"


class FrequencyPeriod(str, Enum):
    daily = "daily"
    weekly = "weekly"
    monthly = "monthly"


class Habit(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    description: Optional[str] = None
    category: Category = Category.other
    frequency_count: int = 1
    frequency_period: FrequencyPeriod = FrequencyPeriod.weekly
    preferred_days: Optional[str] = None  # JSON list: ["Mon","Wed","Fri"]
    notes: Optional[str] = None
    active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)


class HabitLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    habit_id: int = Field(foreign_key="habit.id")
    completed_at: datetime = Field(default_factory=datetime.utcnow)
    notes: Optional[str] = None
    duration_minutes: Optional[int] = None
