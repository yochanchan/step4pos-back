"""POS FastAPI application package."""

from .main import create_app

app = create_app()

__all__ = ("app", "create_app")
