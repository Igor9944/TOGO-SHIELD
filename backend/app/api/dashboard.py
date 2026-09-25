from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.scan import ScanRecord
from app.schemas.scan import DashboardSummary

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def summary(db: Session = Depends(get_db)) -> DashboardSummary:
    total = db.scalar(select(func.count(ScanRecord.id))) or 0
    levels = {level: db.scalar(select(func.count(ScanRecord.id)).where(ScanRecord.level == level)) or 0 for level in ("low", "medium", "critical")}
    telegram = db.scalar(select(func.count(ScanRecord.id)).where(ScanRecord.source == "telegram")) or 0
    urls = db.scalar(select(func.count(ScanRecord.id)).where(ScanRecord.content.like("%http%"))) or 0
    categories = {category: db.scalar(select(func.count(ScanRecord.id)).where(ScanRecord.threat_type == category)) or 0 for category in ("phishing", "suspicious", "low risk")}
    latest = db.scalar(select(ScanRecord.created_at).order_by(ScanRecord.created_at.desc()).limit(1))
    return DashboardSummary(total_scans=total, critical_threats=levels["critical"], medium_risk=levels["medium"], low_risk=levels["low"], urls_analyzed=urls, threats_detected=total - levels["low"], telegram_scans=telegram, last_activity=latest.isoformat() if latest else None, threat_categories=categories, risk_distribution=levels)