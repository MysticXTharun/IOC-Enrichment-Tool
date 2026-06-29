from sqlalchemy import Column, Integer, String, DateTime, Text
from datetime import datetime

from app.database.database import Base


class IOCSearch(Base):
    __tablename__ = "ioc_searches"

    id = Column(Integer, primary_key=True, index=True)

    ioc = Column(String, index=True)

    ioc_type = Column(String)

    source = Column(String)

    response = Column(Text)

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )
