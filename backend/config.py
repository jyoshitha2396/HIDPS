import os
from typing import Optional


DATABASE_ENV_PRIORITY = (
    "DATABASE_URL",
    "NETLIFY_DATABASE_URL_UNPOOLED",
    "NETLIFY_DATABASE_URL",
)


def get_first_env(*names: str) -> tuple[str, str]:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value, name
    return "", ""


def get_database_url() -> str:
    value, _ = get_first_env(*DATABASE_ENV_PRIORITY)
    return value


def get_database_env_source() -> Optional[str]:
    _, source = get_first_env(*DATABASE_ENV_PRIORITY)
    return source or None


def get_allowed_origins() -> list[str]:
    raw_origins = os.getenv("ALLOWED_ORIGINS", "*").strip()
    if raw_origins == "*":
        return ["*"]
    return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
