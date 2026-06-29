from fastapi import FastAPI

app = FastAPI(
    title="IOC Enrichment Tool",
    description="Threat Intelligence IOC Enrichment Platform",
    version="0.1.0"
)

@app.get("/")
async def root():
    return {
        "status": "running",
        "project": "IOC Enrichment Tool",
        "author": "Tharun"
    }
