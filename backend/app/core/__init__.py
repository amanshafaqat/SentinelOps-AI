"""Core application modules: configuration, logging, and error handling."""

from backend.app.core.config import settings
from backend.app.core.logging import setup_logging

__all__ = ["settings", "setup_logging"]
