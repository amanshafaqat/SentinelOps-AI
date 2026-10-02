"""Tests for Configuration Management and Validation."""

from backend.app.core.config import Settings


def test_default_settings():
    """Verify default configuration values."""
    settings = Settings()
    assert settings.app_name in ["SentinelOps AI", "SentinelOps.AI"]
    assert settings.app_version == "1.0.0"
    assert settings.api_v1_prefix == "/api/v1"
    assert settings.api_port in [8000, 8001]
    assert isinstance(settings.cors_origins, list)


def test_cors_origins_parsing():
    """Verify parsing of comma-separated string and JSON list strings."""
    # List format
    s1 = Settings(cors_origins=["http://localhost:3000", "http://127.0.0.1:3000"])
    assert "http://localhost:3000" in s1.cors_origins
    assert "http://127.0.0.1:3000" in s1.cors_origins

    # JSON string format
    s2 = Settings(cors_origins='["https://sec.example.com", "https://soc.example.com"]')
    assert s2.cors_origins == ["https://sec.example.com", "https://soc.example.com"]

    # Comma-separated format
    s3 = Settings(cors_origins="https://a.com, https://b.com")
    assert s3.cors_origins == ["https://a.com", "https://b.com"]


def test_environment_flags():
    """Verify environment property helpers with valid production settings."""
    s_prod = Settings(
        app_env="production",
        debug=False,
        jwt_secret_key="a_very_strong_production_signing_key_at_least_32_characters",
        database_url="postgresql://app_user:strong_password@db.prod.internal:5432/sentinelops_prod",
        cors_origins=["https://soc.sentinelops.example.com"],
    )
    assert s_prod.is_production is True
    assert s_prod.is_testing is False

    s_test = Settings(app_env="testing")
    assert s_test.is_testing is True
    assert s_test.is_production is False


def test_production_config_rejects_insecure_defaults():
    """Verify that production mode strictly rejects default JWT secret or debug=True."""
    import pytest

    with pytest.raises(ValueError, match="Security Error"):
        Settings(app_env="production")

