from __future__ import annotations

from sqlalchemy import create_engine, event, text, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def create_db_engine(
    database_url: str,
    pool_size: int = 10,
    max_overflow: int = 20,
    pool_recycle: int = 3600,
    pool_pre_ping: bool = True,
) -> Engine:
    """
    Crea l'engine SQLAlchemy con connection pooling production-ready.

    Per PostgreSQL: Usa QueuePool con pool_size, max_overflow, pool_recycle
    Per SQLite: Usa StaticPool per in-memory, default per file-based
    """
    connect_args = {}
    pool_args = {}

    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        if database_url.endswith(":memory:"):
            pool_args["poolclass"] = StaticPool
        # SQLite file-based usa il default (QueuePool) con parametri di default
    else:
        # PostgreSQL e altri database - usa pool production-ready
        connect_args["connect_timeout"] = 10
        pool_args["pool_size"] = pool_size
        pool_args["max_overflow"] = max_overflow
        pool_args["pool_recycle"] = pool_recycle
        pool_args["pool_pre_ping"] = pool_pre_ping

    engine = create_engine(database_url, connect_args=connect_args, **pool_args)
    if database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def enable_foreign_keys(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Crea il factory per le sessioni SQLAlchemy."""
    return sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )


def init_db(engine: Engine) -> None:
    """Create the current schema on a fresh database; restarts preserve its data."""
    from app import models  # noqa: F401 — register all tables before create_all

    with engine.begin() as connection:
        inspector = inspect(connection)
        existing = set(inspector.get_table_names())
        if existing:
            # Inspect before any DDL: never partially upgrade a previous database.
            for table in Base.metadata.sorted_tables:
                if table.name not in existing or not set(table.columns.keys()).issubset(
                    {column["name"] for column in inspector.get_columns(table.name)}
                ):
                    raise RuntimeError(
                        "Schema precedente o incompleto: la fase 3 richiede un database nuovo. Nessun dato modificato."
                    )
        Base.metadata.create_all(connection)
        connection.execute(
            text(
                "INSERT INTO bootstrap_lock (id) VALUES (1) ON CONFLICT (id) DO NOTHING"
            )
        )


def check_db_connection(engine: Engine) -> bool:
    """Verifica che la connessione al database sia attiva."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
