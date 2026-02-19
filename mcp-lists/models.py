from datetime import datetime
from enum import Enum
from typing import Optional

from sqlmodel import Field, SQLModel


class ListType(str, Enum):
    shopping = "shopping"
    chores = "chores"
    packing = "packing"
    todo = "todo"
    other = "other"


class Priority(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class List(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    type: ListType = ListType.todo
    location: Optional[str] = None
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class Item(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    list_id: int = Field(foreign_key="list.id")
    title: str
    description: Optional[str] = None
    location: Optional[str] = None
    due_date: Optional[datetime] = None
    priority: Priority = Priority.medium
    category: Optional[str] = None
    completed: bool = False
    completed_at: Optional[datetime] = None
    sort_order: int = 0
    extra_data: Optional[str] = None  # JSON string (renamed: 'metadata' is reserved by SQLAlchemy)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
