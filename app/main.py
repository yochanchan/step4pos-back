from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.exceptions import ApiError, api_error_handler
from app.api.routes import auth, legacy_pos, public


def create_app() -> FastAPI:
    app = FastAPI(title=settings.app_name)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["Authorization", "Content-Type"],
        )

    app.add_exception_handler(ApiError, api_error_handler)

    app.include_router(public.router)
    app.include_router(auth.router)
    app.include_router(legacy_pos.router)

    return app
