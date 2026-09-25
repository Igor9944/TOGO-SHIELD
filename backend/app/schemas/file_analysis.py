"""
Schémas Pydantic pour l'analyse de fichiers.

Structure de la réponse :
- file : métadonnées du fichier
- extracted_content : texte extrait + URLs
- analyses.togo_shield : résultat du moteur interne
- analyses.urlhaus : résultats URLhaus (un par URL)
"""
from __future__ import annotations

from typing import Any

from app.schemas.scan import Indicator, RiskLevel, ScanResult
from pydantic import BaseModel, Field


# ─── Réponse fichier ─────────────────────────────────────────────────────

class FileInfo(BaseModel):
    """Métadonnées du fichier uploadé."""
    filename: str
    type: str  # MIME type ou extension
    size: int
    sha256: str


# ─── Contenu extrait ─────────────────────────────────────────────────────

class ExtractedContent(BaseModel):
    """Résultat de l'extraction depuis le fichier."""
    text: str = ""
    urls: list[str] = Field(default_factory=list)
    ocr_used: bool = False
    ocr_message: str | None = None
    extraction_method: str = "unknown"


# ─── Résultat TOGO-SHIELD (moteur interne) ──────────────────────────────

class TogoShieldAnalysis(BaseModel):
    """Résultat du moteur interne TOGO-SHIELD — score indépendant."""

    engine: str = "togo_shield"
    score: int = 0
    risk_level: str = "low"
    threat_type: str = "low risk"
    confidence: float = 0.0
    indicators: list[Indicator] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    score_breakdown: list[dict[str, Any]] = Field(default_factory=list)

    @classmethod
    def from_scan_result(cls, result: ScanResult, *, from_file: bool = False) -> "TogoShieldAnalysis":
        """Convertit un ScanResult en TogoShieldAnalysis.

        Si from_file=True, le score et les indicateurs sont filtrés pour
        exclure les contributions des sources externes (URLhaus, VirusTotal).
        Le moteur TOGO-SHIELD conserve alors uniquement son analyse interne.
        """
        if from_file:
            # Calculer le score TOGO-SHIELD pur (sans reputation externes)
            local_indicators = [ind for ind in result.indicators if ind.type != "reputation"]
            local_score = sum(ind.weight for ind in local_indicators)
            local_breakdown = [
                sb for sb in result.score_breakdown
                if sb.source not in ("VirusTotal", "URLhaus")
            ]
            local_score = min(local_score, 100)
            local_level = RiskLevel.CRITICAL if local_score >= 70 else RiskLevel.MEDIUM if local_score >= 40 else RiskLevel.LOW
            local_threat_type = (
                "phishing" if any(item.type in {"sensitive_data", "impersonation", "url"} for item in local_indicators)
                else "suspicious" if local_indicators
                else "low risk"
            )
            reasons = [ind.description for ind in local_indicators]
            return cls(
                engine="togo_shield",
                score=local_score,
                risk_level=local_level.value,
                threat_type=local_threat_type,
                confidence=result.confidence,
                indicators=local_indicators,
                recommendations=result.recommendations,
                reasons=reasons,
                score_breakdown=[sb.model_dump() for sb in local_breakdown],
            )

        # Comportement original (pour analyses web/telegram)
        reasons = [ind.description for ind in result.indicators]
        return cls(
            engine="togo_shield",
            score=result.score,
            risk_level=result.level.value,
            threat_type=result.threat_type,
            confidence=result.confidence,
            indicators=result.indicators,
            recommendations=result.recommendations,
            reasons=reasons,
            score_breakdown=[sb.model_dump() for sb in result.score_breakdown],
        )


# ─── Résultat URLhaus ────────────────────────────────────────────────────

class UrlhausAnalysis(BaseModel):
    """Résultat brut d'URLhaus pour une URL — aucun score inventé."""

    source: str = "urlhaus"
    url: str
    found: bool = False
    url_status: str | None = None
    threat: str | None = None
    threat_type: str | None = None
    date_added: str | None = None
    danger_level: int | None = None
    tags: list[str] = Field(default_factory=list)
    status: str = "available"
    error: str | None = None


# ─── Réponse complète ────────────────────────────────────────────────────

class FileAnalysisResponse(BaseModel):
    """Réponse complète de l'analyse de fichier — deux moteurs séparés."""

    file: FileInfo
    extracted_content: ExtractedContent
    analyses: FileAnalyses


class FileAnalyses(BaseModel):
    """Conteneur séparé pour les deux moteurs d'analyse."""

    togo_shield: TogoShieldAnalysis | None = None
    urlhaus: list[UrlhausAnalysis] = Field(default_factory=list)
