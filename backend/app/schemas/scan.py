from enum import StrEnum

from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    CRITICAL = "critical"


class Indicator(BaseModel):
    type: str
    description: str
    weight: int


class ProviderResult(BaseModel):
    provider: str = "unknown"
    known: bool = False
    malicious: bool = False
    detections: int = 0
    total_engines: int = 0
    confidence: float = 0
    evidence: list[str] = Field(default_factory=list)
    status: str = "not_configured"


class ScoreBreakdown(BaseModel):
    source: str
    weight: int


class ScanRequest(BaseModel):
    content: str = Field(min_length=1, max_length=10000)
    source: str = Field(default="web", max_length=32)


class ScanResult(BaseModel):
    score: int
    level: RiskLevel
    threat_type: str
    indicators: list[Indicator]
    recommendations: list[str]
    urls: list[str] = Field(default_factory=list)
    confidence: float = 0
    score_breakdown: list[ScoreBreakdown] = Field(default_factory=list)
    threat_intelligence: list[ProviderResult] = Field(default_factory=list)
    source: str = "web"


class ScanRecordResponse(ScanResult):
    id: int
    content: str
    created_at: str


class DashboardSummary(BaseModel):
    total_scans: int
    critical_threats: int
    medium_risk: int
    low_risk: int
    urls_analyzed: int
    threats_detected: int
    telegram_scans: int
    last_activity: str | None = None
    threat_categories: dict[str, int] = Field(default_factory=dict)
    risk_distribution: dict[str, int] = Field(default_factory=dict)


class TelegramStatus(BaseModel):
    status: str
    bot_username: str = "@TOGOShieldBot"
    configured: bool
    webhook_url: str | None = None