from datetime import datetime
from typing import Any

import json
from sqlalchemy import BigInteger, DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(32), default="web", index=True)
    content: Mapped[str] = mapped_column(Text)
    score: Mapped[int] = mapped_column(Integer, index=True)
    level: Mapped[str] = mapped_column(String(16), index=True)
    threat_type: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    telegram_chat_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    telegram_user_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    telegram_message_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True, unique=True, index=True)
    media_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # ── Métadonnées fichier (nullable, pour les scans via /api/analyze/file) ──
    file_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    file_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    file_size: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    file_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    extracted_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    # ── Fin métadonnées fichier ────────────────────────────────────────────
    indicators_json: Mapped[str] = mapped_column(Text, default="[]")
    threat_intelligence_json: Mapped[str] = mapped_column(Text, default="[]")
    score_breakdown_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "content": self.content,
            "score": self.score,
            "level": self.level,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "telegram_chat_id": self.telegram_chat_id,
            "telegram_user_id": self.telegram_user_id,
            "telegram_message_id": self.telegram_message_id,
            "media_type": self.media_type,
            "file_name": self.file_name,
            "file_type": self.file_type,
            "file_size": self.file_size,
            "file_sha256": self.file_sha256,
            "extracted_text": self.extracted_text,
            "indicators_json": self.indicators_json,
            "threat_intelligence_json": self.threat_intelligence_json,
            "score_breakdown_json": self.score_breakdown_json,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
