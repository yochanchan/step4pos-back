import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ApiError
from app.db.session import get_async_session
from app.services import pos_legacy

router = APIRouter(tags=["pos"])


logger = logging.getLogger(__name__)


@router.get("/item")
async def get_item(
    prd_code: str = Query(...),
    session: AsyncSession = Depends(get_async_session),
) -> dict[str, Any]:
    item = await pos_legacy.get_item_by_identifier(session, prd_code)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    return {
        "prd_id": item.prd_id,
        "code": item.code,
        "name": item.name,
        "price": item.price,
    }


@router.post("/deal")
async def insert_deal(
    payload: dict,
    session: AsyncSession = Depends(get_async_session),
) -> dict[str, str]:
    cart_raw = payload.get("cartpayload") or []
    if isinstance(cart_raw, (str, bytes)):
        raise HTTPException(status_code=400, detail="cartpayload must be an array")

    try:
        cart = [int(product_id) for product_id in cart_raw]
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="cartpayload must be a list of integers")

    amount = payload.get("amountpayload", 0)
    if not isinstance(amount, int):
        raise HTTPException(status_code=400, detail="amountpayload must be an integer")

    try:
        await pos_legacy.create_purchase_with_details(
            session,
            cart_items=cart,
            amount=amount,
        )
        await session.commit()
    except ApiError as exc:
        await session.rollback()
        raise exc
    except Exception:
        await session.rollback()
        logger.exception("deal_insert_error cart=%s amount=%s", cart, amount)
        raise HTTPException(status_code=500, detail="Failed to record deal")

    return {"status": "ok"}
