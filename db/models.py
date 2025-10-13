from sqlalchemy import String, Integer, ForeignKey, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from datetime import datetime

class Base(DeclarativeBase):
    pass



class Items(Base):
    __tablename__ = 'item_code'
    prd_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(13))
    name: Mapped[str] = mapped_column(String(50))
    price: Mapped[int] = mapped_column(Integer)


class Purchases(Base):
    __tablename__ = 'deal'
    TRD_ID: Mapped[int] = mapped_column(Integer, primary_key=True)
    DATETIME: Mapped[datetime] = mapped_column(DateTime)
    EMP_CD: Mapped[str] = mapped_column(String(10))
    STORE_CD: Mapped[str] = mapped_column(String(5))
    POS_NO: Mapped[str] = mapped_column(String(3))
    TOTAL_AMT: Mapped[int] = mapped_column(Integer)

class PurchaseDetails(Base):
    __tablename__ = 'deal_detail'
    TRD_ID: Mapped[int] = mapped_column(Integer, primary_key=True)
    DTL_ID: Mapped[int] = mapped_column(Integer, primary_key=True)
    PRD_ID: Mapped[int] = mapped_column(Integer)
    PRD_CODE: Mapped[str] = mapped_column(String(13))
    PRD_NAME: Mapped[str] = mapped_column(String(50))
    PRD_PRICE: Mapped[int] = mapped_column(Integer)