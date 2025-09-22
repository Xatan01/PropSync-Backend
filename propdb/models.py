import sqlalchemy
from .db import metadata
import datetime

agents = sqlalchemy.Table(
    "agents",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String, primary_key=True),  # Cognito sub
    sqlalchemy.Column("name", sqlalchemy.String),
    sqlalchemy.Column("email", sqlalchemy.String, unique=True),
    sqlalchemy.Column("phone", sqlalchemy.String),
    sqlalchemy.Column("avatar", sqlalchemy.String),
    sqlalchemy.Column("plan", sqlalchemy.String, default="starter"),
    sqlalchemy.Column(
        "member_since",
        sqlalchemy.DateTime,
        default=datetime.datetime.utcnow,  # auto-populate on insert
        nullable=False
    ),
)

clients = sqlalchemy.Table(
    "clients",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("agent_id", sqlalchemy.String, sqlalchemy.ForeignKey("agents.id")),
    sqlalchemy.Column("name", sqlalchemy.String),
    sqlalchemy.Column("email", sqlalchemy.String),
    sqlalchemy.Column("phone", sqlalchemy.String),
    sqlalchemy.Column("avatar", sqlalchemy.String),
)


