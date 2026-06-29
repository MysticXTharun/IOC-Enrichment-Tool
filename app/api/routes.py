from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
import json

from app.utils.ioc_detector import detect_ioc
from app.services.abuseipdb import check_ip

from app.database.database import get_db
from app.database.crud import (
    get_cached_ioc,
    save_ioc,
    get_history,
    get_history_by_id,
    delete_history,
)

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
def enrich(request: IOCRequest, db: Session = Depends(get_db)):
    ioc_type = detect_ioc(request.ioc)

    # Check SQLite cache first
    cached = get_cached_ioc(db, request.ioc)

    if cached:
        return {
            "ioc": cached.ioc,
            "type": cached.ioc_type,
            "source": cached.source,
            "cached": True,
            "response": json.loads(cached.response)
        }

    if ioc_type in ("ipv4", "ipv6"):
        result = check_ip(request.ioc)

        save_ioc(
            db=db,
            ioc=request.ioc,
            ioc_type=ioc_type,
            source="AbuseIPDB",
            response=result
        )

        return {
            "ioc": request.ioc,
            "type": ioc_type,
            "source": "AbuseIPDB",
            "cached": False,
            "response": result
        }

    raise HTTPException(
        status_code=400,
        detail="IOC type not yet supported"
    )

@router.get("/history")
def history(db: Session = Depends(get_db)):
    records = get_history(db)

    return [
        {
            "id": record.id,
            "ioc": record.ioc,
            "type": record.ioc_type,
            "source": record.source,
            "created_at": record.created_at,
        }
        for record in records
    ]


@router.get("/history/{record_id}")
def history_by_id(record_id: int, db: Session = Depends(get_db)):
    record = get_history_by_id(db, record_id)

    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    return {
        "id": record.id,
        "ioc": record.ioc,
        "type": record.ioc_type,
        "source": record.source,
        "response": json.loads(record.response),
        "created_at": record.created_at,
    }


@router.delete("/history/{record_id}")
def remove_history(record_id: int, db: Session = Depends(get_db)):
    record = delete_history(db, record_id)

    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    return {
        "message": "IOC removed successfully"
    }
