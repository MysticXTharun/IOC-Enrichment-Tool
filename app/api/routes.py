from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
import json
from concurrent.futures import ThreadPoolExecutor

from app.utils.ioc_detector import detect_ioc

from app.services.abuseipdb import check_ip

from app.services.scoring import score_ip

from app.services.otx import (
    check_ip as check_otx_ip,
    check_domain as check_otx_domain,
    check_url as check_otx_url,
)

from app.services.virustotal import (
    check_ip as check_vt_ip,
    check_domain as check_vt_domain,
    check_url as check_vt_url,
    check_hash as check_vt_hash,
)

from app.services.summary import summarize_ip

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

    # Check cache first
    cached = get_cached_ioc(db, request.ioc)

    if cached:
        return {
            "ioc": cached.ioc,
            "type": cached.ioc_type,
            "source": cached.source,
            "cached": True,
            "response": json.loads(cached.response),
        }

    # -------------------------
    # IP Addresses
    # -------------------------

    if ioc_type in ("ipv4", "ipv6"):

        with ThreadPoolExecutor(max_workers=3) as executor:

            abuse_future = executor.submit(check_ip, request.ioc)
            otx_future = executor.submit(check_otx_ip, request.ioc)
            vt_future = executor.submit(check_vt_ip, request.ioc)

            abuse_result = abuse_future.result()
            otx_result = otx_future.result()
            vt_result = vt_future.result()

        summary = summarize_ip(
            abuse_result,
            otx_result,
            vt_result,
        )

        score = score_ip(
            abuse_result,
            otx_result,
            vt_result,
        )

        combined_result = {
            "summary": summary,
            "score": score,
            "abuseipdb": abuse_result,
            "otx": otx_result,
            "virustotal": vt_result,
        }

        save_ioc(
            db=db,
            ioc=request.ioc,
            ioc_type=ioc_type,
            source="AbuseIPDB + OTX + VirusTotal",
            response=combined_result,
        )

        return {
            "ioc": request.ioc,
            "type": ioc_type,
            "source": "AbuseIPDB + OTX + VirusTotal",
            "cached": False,
            "response": combined_result,
        }
    
    # -------------------------
    # Domains
    # -------------------------

    if ioc_type == "domain":

        otx_result = check_otx_domain(request.ioc)
        vt_result = check_vt_domain(request.ioc)

        combined_result = {
            "otx": otx_result,
            "virustotal": vt_result,
        }

        save_ioc(
            db=db,
            ioc=request.ioc,
            ioc_type=ioc_type,
            source="OTX + VirusTotal",
            response=combined_result,
        )

        return {
            "ioc": request.ioc,
            "type": ioc_type,
            "source": "OTX + VirusTotal",
            "cached": False,
            "response": combined_result,
        }

    # -------------------------
    # URLs
    # -------------------------

    if ioc_type == "url":

        otx_result = check_otx_url(request.ioc)
        vt_result = check_vt_url(request.ioc)

        combined_result = {
            "otx": otx_result,
            "virustotal": vt_result,
        }

        save_ioc(
            db=db,
            ioc=request.ioc,
            ioc_type=ioc_type,
            source="OTX + VirusTotal",
            response=combined_result,
        )

        return {
            "ioc": request.ioc,
            "type": ioc_type,
            "source": "OTX + VirusTotal",
            "cached": False,
            "response": combined_result,
        }

    # -------------------------
    # File Hashes
    # -------------------------

    if ioc_type in ("md5", "sha1", "sha256"):

        vt_result = check_vt_hash(request.ioc)

        combined_result = {
            "virustotal": vt_result,
        }

        save_ioc(
            db=db,
            ioc=request.ioc,
            ioc_type=ioc_type,
            source="VirusTotal",
            response=combined_result,
        )

        return {
            "ioc": request.ioc,
            "type": ioc_type,
            "source": "VirusTotal",
            "cached": False,
            "response": combined_result,
        }

    raise HTTPException(
        status_code=400,
        detail="IOC type not yet supported for enrichment",
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
