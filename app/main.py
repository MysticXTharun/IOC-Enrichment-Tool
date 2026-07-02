from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.dashboard import router as dashboard_router
from app.database.database import Base, engine
from app.database import models

Base.metadata.create_all(bind=engine)

from app.api.routes import router

app = FastAPI(title="IOC Enrichment Tool")

# -----------------------------
# Static files
# -----------------------------
app.mount("/static", StaticFiles(directory="static"), name="static")

# -----------------------------
# HTML Templates
# -----------------------------
templates = Jinja2Templates(directory="templates")

# -----------------------------
# API Routes
# -----------------------------
app.include_router(router)
app.include_router(dashboard_router)

# -----------------------------
# Dashboard
# -----------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
    )

# -----------------------------
# Health Check
# -----------------------------
@app.get("/health")
def health():
    return {
        "status": "running",
        "project": "IOC Enrichment Tool",
        "author": "Tharun",
    }
