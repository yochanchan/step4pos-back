from __future__ import annotations

from datetime import datetime
from typing import Iterable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ApiError
from app.db.models import Item, Purchase, PurchaseDetail


async def get_item_by_identifier(
    session: AsyncSession,
    identifier: str,
) -> Optional[Item]:
    """Fetch an item either by product code or numeric ID."""
    stmt = select(Item).where(Item.code == identifier)
    result = await session.execute(stmt)
    item = result.scalar_one_or_none()
    if item is not None:
        return item

    if identifier.isdigit():
        id_stmt = select(Item).where(Item.prd_id == int(identifier))
        id_result = await session.execute(id_stmt)
        return id_result.scalar_one_or_none()

    return None


async def create_purchase_with_details(
    session: AsyncSession,
    *,
    cart_items: Iterable[int],
    amount: int,
) -> None:
    cart = list(cart_items)
    if not cart:
        raise ApiError(
            code="cart_empty",
            message="No items selected for purchase.",
            status_code=400,
        )

    purchase = Purchase(
        datetime=datetime.utcnow(),
        emp_cd="9999999999",
        store_cd="00030",
        pos_no="090",
        total_amt=amount,
    )
    session.add(purchase)
    await session.flush()

    dtl_id = 1
    for product_id in cart:
        item_stmt = select(Item).where(Item.prd_id == product_id)
        item = await session.execute(item_stmt)
        item_obj = item.scalar_one_or_none()
        if item_obj is None:
            raise ApiError(
                code="item_not_found",
                message="Selected item was not found.",
                status_code=404,
            )

        detail = PurchaseDetail(
            trd_id=purchase.trd_id,
            dtl_id=dtl_id,
            prd_id=item_obj.prd_id,
            prd_code=item_obj.code,
            prd_name=item_obj.name,
            prd_price=item_obj.price,
        )
        session.add(detail)
        dtl_id += 1

    await session.flush()
