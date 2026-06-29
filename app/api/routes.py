from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.utils.ioc_detector import detect_ioc
from app.services.abuseipdb import check_ip

router = APIRouter()


class IOCRequest(BaseModel):
    ioc: str


@router.post("/detect")
def detect(request: IOCRequest):
    return {
        "ioc": request.ioc,
        "type": detect_ioc(request.ioc),
    }


@router.post("/enrich")
def enrich(request: IOCRequest):
    ioc_type = detect_ioc(request.ioc)

    if ioc_type in ("ipv4", "ipv6"):
        return {
            "ioc": request.ioc,
            "type": ioc_type,
            "abuseipdb": check_ip(request.ioc),
        }

    raise HTTPException(
        status_code=400,
        detail="IOC type not yet supported for enrichment",
    )
