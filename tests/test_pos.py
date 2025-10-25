from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db.models import Item, Purchase, PurchaseDetail
from app.db.session import AsyncSessionLocal


@pytest.mark.asyncio
async def test_get_item_and_record_deal(client):
    code = "1234567890123"
    async with AsyncSessionLocal() as session:
        session.add(
            Item(
                prd_id=1,
                code=code,
                name="Test Product",
                price=500,
            )
        )
        await session.commit()

    response = await client.get("/item", params={"prd_code": code})
    assert response.status_code == 200
    item = response.json()
    assert item["name"] == "Test Product"
    assert item["price"] == 500

    deal_response = await client.post(
        "/deal",
        json={"cartpayload": [1], "amountpayload": 500},
    )
    assert deal_response.status_code == 200
    assert deal_response.json() == {"status": "ok"}

    async with AsyncSessionLocal() as session:
        purchases = (await session.execute(select(Purchase))).scalars().all()
        assert len(purchases) == 1
        details = (await session.execute(select(PurchaseDetail))).scalars().all()
        assert len(details) == 1
        assert details[0].prd_code == code


@pytest.mark.asyncio
async def test_deal_validates_payload_shape(client):
    response = await client.post(
        "/deal",
        json={"cartpayload": "not-a-list", "amountpayload": 100},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "cartpayload must be an array"
