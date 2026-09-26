from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.api.dashboard import router as dashboard_router
from app.api.scans import router as scans_router
from app.api.file_analysis import router as file_analysis_router
from app.api.telegram import router as telegram_router
from app.core.database import ensure_production_schema
from app.telegram.service import ensure_webhook


settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_origin_regex=r"^https://togo-shield(?:-web)?(?:-[a-z0-9-]+)?\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


app.include_router(file_analysis_router)
app.include_router(scans_router)
app.include_router(dashboard_router)
app.include_router(telegram_router)


@app.on_event("startup")
async def startup_checks() -> None:
    ensure_production_schema()
    if settings.telegram_enabled:
        await ensure_webhook()
