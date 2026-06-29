from fastapi import FastAPI

from app.database.database import Base, engine
from app.database import models

Base.metadata.create_all(bind=engine)

from app.api.routes import router

app = FastAPI(title="IOC Enrichment Tool")

app.include_router(router)


@app.get("/")
def root():
    return {
        "status": "running",
        "project": "IOC Enrichment Tool",
        "author": "Tharun",
    }
