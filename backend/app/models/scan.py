from datetime import datetime

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
    indicators_json: Mapped[str] = mapped_column(Text, default="[]")
    threat_intelligence_json: Mapped[str] = mapped_column(Text, default="[]")
    score_breakdown_json: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
