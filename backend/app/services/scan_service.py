import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.scan import ScanRecord
from app.schemas.scan import ScanRecordResponse, ScanRequest, ScanResult
from app.services.risk_engine import assess_risk


def analyze_and_persist(request: ScanRequest, db: Session, *, telegram: dict[str, int] | None = None, media_type: str | None = None) -> ScanResult:
    result = assess_risk(request.content, source=request.source)
    record = ScanRecord(
        source=request.source,
        content=request.content,
        score=result.score,
        level=result.level.value,
        threat_type=result.threat_type,
        confidence=round(result.confidence * 100),
        telegram_chat_id=telegram.get("chat_id") if telegram else None,
        telegram_user_id=telegram.get("user_id") if telegram else None,
        telegram_message_id=telegram.get("message_id") or None if telegram else None,
        media_type=media_type,
        indicators_json=json.dumps([item.model_dump() for item in result.indicators], ensure_ascii=False),
        threat_intelligence_json=json.dumps([item.model_dump() for item in result.threat_intelligence], ensure_ascii=False),
        score_breakdown_json=json.dumps([item.model_dump() for item in result.score_breakdown], ensure_ascii=False),
    )
    db.add(record)
    db.commit()
    return result


def to_response(record: ScanRecord) -> ScanRecordResponse:
    return ScanRecordResponse(
        id=record.id,
        content=record.content,
        score=record.score,
        level=record.level,
        threat_type=record.threat_type,
        confidence=record.confidence / 100,
        indicators=json.loads(record.indicators_json or "[]"),
        threat_intelligence=json.loads(record.threat_intelligence_json or "[]"),
        score_breakdown=json.loads(record.score_breakdown_json or "[]"),
        recommendations=["Ne cliquez pas sur les liens suspects.", "Ne communiquez jamais votre OTP, PIN ou mot de passe."],
        urls=[],
        source=record.source,
        created_at=record.created_at.isoformat() if record.created_at else "",
    )


def list_records(db: Session, limit: int = 50) -> list[ScanRecordResponse]:
    return [to_response(record) for record in db.scalars(select(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(limit)).all()]