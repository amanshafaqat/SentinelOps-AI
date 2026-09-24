"""Database Engine, Session Architecture, and Connectivity Checks.

Configures connection pooling, scoped sessions, and safe dependency injection
for FastAPI endpoints. Includes non-blocking connection verification.
"""

import time
from typing import Generator, Dict, Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError
from backend.app.core.config import settings
from backend.app.core.logging import logger


def get_engine_args(db_url: str) -> Dict[str, Any]:
    """Generates engine arguments tailored to the database dialect."""
    args: Dict[str, Any] = {
        "echo": settings.database_echo,
    }
    if db_url.startswith("sqlite"):
        args["connect_args"] = {"check_same_thread": False}
    else:
        args["pool_size"] = settings.database_pool_size
        args["max_overflow"] = settings.database_max_overflow
        args["pool_pre_ping"] = True
    return args


# Engine and Session Factory
engine = create_engine(settings.database_url, **get_engine_args(settings.database_url))
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a scoped database session with automatic cleanup."""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def check_database_connection() -> Dict[str, Any]:
    """Verifies live database connectivity and measures roundtrip latency.

    Returns structured status without raising exceptions to ensure the health
    endpoint stays resilient even if the database is temporarily unreachable.
    """
    start_time = time.perf_counter()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "status": "connected",
            "dialect": engine.dialect.name,
            "latency_ms": latency_ms,
            "error": None,
        }
    except SQLAlchemyError as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.warning(f"Database health check failed ({engine.dialect.name}): {str(exc)}")
        return {
            "status": "disconnected",
            "dialect": engine.dialect.name,
            "latency_ms": latency_ms,
            "error": "Connection failed. Please ensure PostgreSQL is running.",
        }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "status": "error",
            "dialect": engine.dialect.name,
            "latency_ms": latency_ms,
            "error": str(exc),
        }
