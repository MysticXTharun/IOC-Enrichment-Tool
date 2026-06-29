import json

from sqlalchemy.orm import Session

from app.database.models import IOCSearch


def get_cached_ioc(db: Session, ioc: str):
    return (
        db.query(IOCSearch)
        .filter(IOCSearch.ioc == ioc)
        .first()
    )


def save_ioc(
    db: Session,
    ioc: str,
    ioc_type: str,
    source: str,
    response: dict,
):
    entry = IOCSearch(
        ioc=ioc,
        ioc_type=ioc_type,
        source=source,
        response=json.dumps(response),
    )

    db.add(entry)
    db.commit()
    db.refresh(entry)

    return entry
