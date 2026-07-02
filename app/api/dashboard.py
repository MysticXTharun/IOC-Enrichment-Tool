from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.database import get_db
from app.database.models import IOCSearch

router = APIRouter()


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):

    total = db.query(IOCSearch).count()

    ip_count = db.query(IOCSearch).filter(
        IOCSearch.ioc_type.in_(["ipv4", "ipv6"])
    ).count()

    domain_count = db.query(IOCSearch).filter(
        IOCSearch.ioc_type == "domain"
    ).count()

    url_count = db.query(IOCSearch).filter(
        IOCSearch.ioc_type == "url"
    ).count()

    hash_count = db.query(IOCSearch).filter(
        IOCSearch.ioc_type.in_(["md5", "sha1", "sha256"])
    ).count()

    recent = (
        db.query(IOCSearch)
        .order_by(IOCSearch.created_at.desc())
        .limit(5)
        .all()
    )

    return {
        "total_iocs": total,
        "ioc_types": {
            "ip": ip_count,
            "domain": domain_count,
            "url": url_count,
            "hash": hash_count,
        },
        "recent": [
            {
                "ioc": x.ioc,
                "type": x.ioc_type,
                "time": x.created_at.isoformat(),   # Convert datetime to string
            }
            for x in recent
        ],
    }
