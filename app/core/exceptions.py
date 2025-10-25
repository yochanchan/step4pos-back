from fastapi import Request
from fastapi.responses import JSONResponse


class ApiError(Exception):
    """Generic API error used for consistent response formatting."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 400,
        hint: str | None = None,
    ) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code
        self.hint = hint


async def api_error_handler(_: Request, exc: ApiError) -> JSONResponse:
    payload = {"error": {"code": exc.code, "message": exc.message}}
    if exc.hint:
        payload["error"]["hint"] = exc.hint
    return JSONResponse(status_code=exc.status_code, content=payload)
