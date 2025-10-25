import os
from functools import lru_cache
from typing import List, Optional

from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _normalize_same_site(value: str | None) -> Optional[str]:
    if value is None:
        return None
    lowered = value.lower()
    if lowered in {"lax", "strict", "none"}:
        return lowered
    return "lax"


class Settings(BaseModel):
    """Application configuration sourced from environment variables."""

    app_name: str = "POS FastAPI"
    database_url: str = ""
    database_echo: bool = False
    database_ssl_ca_path: Optional[str] = None
    cors_origins: List[str] = Field(default_factory=list)

    jwt_secret: str = ""
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 14
    refresh_cookie_name: str = "pos_refresh_token"
    refresh_cookie_domain: Optional[str] = None
    refresh_cookie_secure: bool = True
    refresh_cookie_path: str = "/"
    refresh_cookie_same_site: Optional[str] = "lax"

    line_client_id: Optional[str] = None
    line_client_secret: Optional[str] = None
    line_redirect_uri: Optional[str] = None

    @classmethod
    def load(cls) -> "Settings":
        raw_origins = os.getenv("CORS_ORIGINS", "")
        origins = [
            origin.strip()
            for origin in raw_origins.split(",")
            if origin.strip()
        ]
        if not origins:
            origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

        database_url = os.getenv("DATABASE_URL", "")
        if not database_url:
            # fall back to legacy discrete DB_* variables
            db_user = os.getenv("DB_USER")
            db_password = os.getenv("DB_PASSWORD")
            db_host = os.getenv("DB_HOST")
            db_port = os.getenv("DB_PORT", "3306")
            db_name = os.getenv("DB_NAME")
            if all([db_user, db_password, db_host, db_name]):
                database_url = (
                    f"mysql+asyncmy://{db_user}:{db_password}"
                    f"@{db_host}:{db_port}/{db_name}?charset=utf8mb4"
                )

        return cls(
            cors_origins=origins,
            database_url=database_url,
            database_echo=_env_bool("DATABASE_ECHO", False),
            database_ssl_ca_path=os.getenv("SSL_CA_PATH"),
            jwt_secret=os.getenv("JWT_SECRET", ""),
            access_token_ttl_minutes=int(os.getenv("ACCESS_TOKEN_TTL_MIN", "15")),
            refresh_token_ttl_days=int(os.getenv("REFRESH_TOKEN_TTL_DAY", "14")),
            refresh_cookie_name=os.getenv("REFRESH_COOKIE_NAME", "pos_refresh_token"),
            refresh_cookie_domain=os.getenv("REFRESH_COOKIE_DOMAIN"),
            refresh_cookie_secure=_env_bool("REFRESH_COOKIE_SECURE", True),
            refresh_cookie_path=os.getenv("REFRESH_COOKIE_PATH", "/"),
            refresh_cookie_same_site=_normalize_same_site(os.getenv("REFRESH_COOKIE_SAMESITE", "lax")),
            line_client_id=os.getenv("OIDC_LINE_CLIENT_ID"),
            line_client_secret=os.getenv("OIDC_LINE_CLIENT_SECRET"),
            line_redirect_uri=os.getenv("OIDC_LINE_REDIRECT_URI"),
        )


@lru_cache
def get_settings() -> Settings:
    return Settings.load()


settings = get_settings()
