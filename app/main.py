from fastapi import FastAPI
from app.api.routes import router

app = FastAPI(
    title="IOC Enrichment Tool",
    version="0.1.0"
)

app.include_router(router)


@app.get("/")
async def root():
    return {
        "status": "running",
        "project": "IOC Enrichment Tool"
    }
