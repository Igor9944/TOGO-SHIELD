"""Schémas Pydantic pour l'analyse IA (Google Gemini)."""
from __future__ import annotations

from pydantic import BaseModel, Field


class AIExplanation(BaseModel):
    """Explication détaillée du score fournie par Gemini."""
    summary: str = Field(..., description="Résumé concis en français (1-3 phrases)")
    details: list[str] = Field(default_factory=list, description="Points détaillés")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Confiance de l'IA dans son analyse")


class AIClassification(BaseModel):
    """Classification de la menace fournie par Gemini."""
    category: str = Field(..., description="Catégorie : phishing, smishing, arnaque, reconnaissance, autre")
    sub_category: str | None = Field(default=None, description="Sous-catégorie optionnelle")
    severity_assessment: str = Field(..., description="Avis de sévérité : low, medium, high, critical")


class AIAnalysis(BaseModel):
    """Résultat complet de l'analyse IA."""
    explanation: AIExplanation | None = None
    classification: AIClassification | None = None
    provider: str = "google"
    model: str = "gemini-3.8-flash"
    latency_ms: int | None = None
    status: str = "not_used"  # available, unavailable, not_configured, error
    error: str | None = None


class AnalysisContext(BaseModel):
    """Données sécurisées envoyées à Gemini."""
    content: str = Field(..., description="Contenu du message (déjà nettoyé par le Risk Engine)")
    score: int = Field(..., ge=0, le=100, description="Score du Risk Engine")
    level: str = Field(..., description="Niveau : low, medium, critical")
    threat_type: str = Field(..., description="Type de menace du Risk Engine")
    indicators: list[dict] = Field(default_factory=list, description="Indicateurs détectés")
    urls: list[str] = Field(default_factory=list, description="URLs extraites")
