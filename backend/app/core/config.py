"""Application Configuration Management.

Uses Pydantic BaseSettings for strong typing, environment variable parsing,
and validation. Secrets are loaded strictly from the environment.
"""

from typing import List, Union
import json
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # General Application Settings
    app_name: str = Field(default="SentinelOps AI", description="Name of the application")
    app_env: str = Field(default="development", description="Environment: development, staging, production, testing")
    app_version: str = Field(default="1.0.0", description="Semantic application version")
    debug: bool = Field(default=False, description="Debug mode flag")
    log_level: str = Field(default="INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")

    # Server Configuration
    api_host: str = Field(default="0.0.0.0", description="Host interface to bind")
    api_port: int = Field(default=8001, description="Port to bind")
    api_v1_prefix: str = Field(default="/api/v1", description="V1 API route prefix")

    # CORS Configuration
    cors_origins: Union[List[str], str] = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000"],
        description="Allowed CORS origins"
    )

    # Database Configuration (PostgreSQL by default)
    database_url: str = Field(
        default="postgresql://postgres:postgres@localhost:5432/sentinelops",
        description="SQLAlchemy Database URL (PostgreSQL)"
    )
    database_echo: bool = Field(default=False, description="Echo raw SQL statements")
    database_pool_size: int = Field(default=5, description="Connection pool size")
    database_max_overflow: int = Field(default=10, description="Max overflow connections")

    # Security & Authentication (Foundation for future phases)
    jwt_secret_key: str = Field(
        default="sentinelops-dev-secret-key-change-in-production",
        description="Secret key for JWT token verification"
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT signing algorithm")
    access_token_expire_minutes: int = Field(default=60, description="Access token expiration in minutes")

    # Gemini AI Configuration (Backend-only, future Phase 5)
    gemini_api_key: str = Field(default="", description="Gemini API Key - server side only")
    gemini_model: str = Field(default="gemini-2.5-flash", description="Default Gemini model")

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: Union[str, List[str]]) -> List[str]:
        if isinstance(value, str):
            value = value.strip()
            if value.startswith("[") and value.endswith("]"):
                try:
                    parsed = json.loads(value)
                    if isinstance(parsed, list):
                        return [str(item).strip() for item in parsed if str(item).strip()]
                except json.JSONDecodeError:
                    pass
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        elif isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return ["*"]

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    @property
    def is_testing(self) -> bool:
        return self.app_env.lower() == "testing"


# Singleton instance
settings = Settings()
