from fastapi import APIRouter

router = APIRouter(tags=["public"])


@router.get("/")
async def hello() -> dict[str, str]:
    return {"message": "hello!"}
