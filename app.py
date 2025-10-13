from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import json
from typing import List
from db.models import Items, Purchases, PurchaseDetails
from db.crud import myselect, myinsert

app = FastAPI()

class DealPayload(BaseModel):
    cartpayload: List[int]
    amountpayload: int


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://app-002-gen10-step3-1-node-oshima31.azurewebsites.net",
        "rdbs-002-gen10-step3-1-oshima3.mysql.database.azure.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EchoMessage(BaseModel):
    message: str

@app.get("/")
def hello():
    return {"message": "hello!"}

@app.get("/item")
def get_item (prd_code: str = Query(...)):
    result = myselect(Items, prd_code)
    if not result:
        raise HTTPException(status_code=404, detail="Customer not found")
    result_obj = json.loads(result)
    return result_obj[0] if result_obj else None

@app.post("/deal")
def insert_deal (payload: DealPayload):
    cart = payload.cartpayload
    amount = payload.amountpayload

    result = myinsert(cart, amount)
    if not result:
        raise HTTPException(status_code=404, detail="Customer not found")



@app.exception_handler(RequestValidationError)
async def handler(request:Request, exc:RequestValidationError):
    print(exc)
    return JSONResponse(content={}, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)
