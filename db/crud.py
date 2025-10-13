
from sqlalchemy import create_engine, insert, delete, update, select
import sqlalchemy
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func
import json
import pandas as pd
import datetime
from db.connect import engine
from db.models import Items, Purchases, PurchaseDetails



def myselect(model, prd_id):
    # session構築
    Session = sessionmaker(bind=engine)
    session = Session()
    query = session.query(model).filter(model.prd_id == prd_id)
    try:
        # トランザクションを開始
        with session.begin():
            result = query.all()
        # 結果をオブジェクトから辞書に変換し、リストに追加
        result_dict_list = []
        for item_info in result:
            result_dict_list.append({
                "prd_id": item_info.prd_id,
                "code": item_info.code,
                "name": item_info.name,
                "price": item_info.price
            })
        # リストをJSONに変換
        result_json = json.dumps(result_dict_list, ensure_ascii=False)
    except sqlalchemy.exc.IntegrityError:
        print("一意制約違反により、挿入に失敗しました")

    # セッションを閉じる
    session.close()
    return result_json


def myinsert(cart, amount):
    # session構築
    Session = sessionmaker(bind=engine)
    session = Session()

    dt_now = datetime.datetime.now()

    query1 = insert(Purchases)
    v_deal = [{
        "TRD_ID": 0,
        "DATETIME": dt_now,
        "EMP_CD": "9999999999",
        "STORE_CD": "00030",
        "POS_NO": "090",
        "TOTAL_AMT": amount,
    }]


    


    try:
        # トランザクションを開始
        with session.begin():
            # データの挿入
            result1 = session.execute(query1.values(v_deal))
            query2 = select(func.max(Purchases.TRD_ID).label("max_no"))
            max = session.scalars(query2).one()

            result_code = session.scalars(select(Items.code).where(Items.prd_id == 1)).one()
            result_name = session.scalars(select(Items.name).where(Items.prd_id == 1)).one()
            result_price = session.scalars(select(Items.price).where(Items.prd_id == 1)).one()

            query3 = insert(PurchaseDetails)

            cart = cart
            for i in cart:
                result_code = session.scalars(select(Items.code).where(Items.prd_id == i)).one()
                result_name = session.scalars(select(Items.name).where(Items.prd_id == i)).one()
                result_price = session.scalars(select(Items.price).where(Items.prd_id == i)).one()

                v_detail = [{
                    "TRD_ID": max,
                    "DTL_ID": 0,
                    "PRD_ID": i,
                    "PRD_CODE": result_code,
                    "PRD_NAME": result_name,
                    "PRD_PRICE": result_price,
                }]
                result3 = session.execute(query3.values(v_detail))
    except sqlalchemy.exc.IntegrityError:
        print("一意制約違反により、挿入に失敗しました")
        session.rollback()

    # セッションを閉じる
    session.close()
    print(max)
    return "inserted"


