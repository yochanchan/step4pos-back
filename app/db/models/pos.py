from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Item(Base):
    __tablename__ = "item_code"

    prd_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(13), nullable=False)
    name: Mapped[str] = mapped_column(String(50), nullable=False)
    price: Mapped[int] = mapped_column(Integer, nullable=False)

    details: Mapped[list["PurchaseDetail"]] = relationship("PurchaseDetail", back_populates="item")


class Purchase(Base):
    __tablename__ = "deal"

    trd_id: Mapped[int] = mapped_column(
        "TRD_ID",
        Integer,
        primary_key=True,
    )
    datetime: Mapped[datetime] = mapped_column("DATETIME", DateTime, nullable=False)
    emp_cd: Mapped[str] = mapped_column("EMP_CD", String(10), nullable=False)
    store_cd: Mapped[str] = mapped_column("STORE_CD", String(5), nullable=False)
    pos_no: Mapped[str] = mapped_column("POS_NO", String(3), nullable=False)
    total_amt: Mapped[int] = mapped_column("TOTAL_AMT", Integer, nullable=False)

    details: Mapped[list["PurchaseDetail"]] = relationship("PurchaseDetail", back_populates="purchase")


class PurchaseDetail(Base):
    __tablename__ = "deal_detail"

    trd_id: Mapped[int] = mapped_column(
        "TRD_ID",
        ForeignKey("deal.TRD_ID", onupdate="CASCADE", ondelete="CASCADE"),
        primary_key=True,
    )
    dtl_id: Mapped[int] = mapped_column("DTL_ID", Integer, primary_key=True)
    prd_id: Mapped[int] = mapped_column(
        "PRD_ID",
        ForeignKey("item_code.prd_id", onupdate="CASCADE", ondelete="RESTRICT"),
        nullable=False,
    )
    prd_code: Mapped[str] = mapped_column("PRD_CODE", String(13), nullable=False)
    prd_name: Mapped[str] = mapped_column("PRD_NAME", String(50), nullable=False)
    prd_price: Mapped[int] = mapped_column("PRD_PRICE", Integer, nullable=False)

    purchase: Mapped["Purchase"] = relationship(
        "Purchase",
        back_populates="details",
        primaryjoin="PurchaseDetail.trd_id == Purchase.trd_id",
    )
    item: Mapped[Optional["Item"]] = relationship(
        "Item",
        back_populates="details",
        primaryjoin="PurchaseDetail.prd_id == Item.prd_id",
    )
