from fastapi import APIRouter
from pydantic import BaseModel

from app.utils.ioc_detector import detect_ioc

router = APIRouter()


class IOCRequest(BaseModel):
    ioc: str


@router.post("/detect")
async def detect(request: IOCRequest):
    return {
        "ioc": request.ioc,
        "type": detect_ioc(request.ioc)
    }
