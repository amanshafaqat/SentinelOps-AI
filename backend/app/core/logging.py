"""Logging Foundation for SentinelOps AI.

Configures structured logging with built-in sensitive data masking
(redacts authorization headers, API keys, tokens, passwords, and private keys).
"""

import logging
import re
import sys
from typing import Any
from backend.app.core.config import settings

# Sensitive keyword patterns to redact
SENSITIVE_PATTERNS = [
    (re.compile(r'(["\']?(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|bearer)["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1***REDACTED***\3'),
    (re.compile(r'(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*', re.IGNORECASE), r'\1***REDACTED***'),
    (re.compile(r'(AIzaSy[A-Za-z0-9_-]{33})', re.IGNORECASE), r'***REDACTED_GEMINI_KEY***'),
]


class SensitiveDataFilter(logging.Filter):
    """Filters log records to redact potential credentials, tokens, and secrets."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.sanitize(record.msg)
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(
                    self.sanitize(arg) if isinstance(arg, str) else arg
                    for arg in record.args
                )
            elif isinstance(record.args, dict):
                record.args = {
                    k: self.sanitize(v) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
        return True

    @staticmethod
    def sanitize(text: str) -> str:
        for pattern, replacement in SENSITIVE_PATTERNS:
            text = pattern.sub(replacement, text)
        return text


def setup_logging() -> None:
    """Configures application-wide logging with safety filters and uniform format."""
    log_level_name = settings.log_level.upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    log_format = (
        "[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d] "
        "[env:%(environment)s] - %(message)s"
    )

    class ContextInjectingFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            if not hasattr(record, "environment"):
                record.environment = settings.app_env
            return super().format(record)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(log_level)
    handler.addFilter(SensitiveDataFilter())
    handler.setFormatter(ContextInjectingFormatter(fmt=log_format, datefmt="%Y-%m-%d %H:%M:%S"))

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    # Clear existing handlers to avoid duplicates
    root_logger.handlers.clear()
    root_logger.addHandler(handler)

    # Quieten overly noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


logger = logging.getLogger("sentinelops")
