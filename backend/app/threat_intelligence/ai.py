"""
Provider d'analyse IA (Google Gemini).

 Séparé du moteur TOGO-SHIELD. Retourne une analyse structurée
 (AIAnalysis) sans modifier le score du Risk Engine.
"""
from __future__ import annotations

from typing import Any

from app.schemas.ai import AIAnalysis
from app.services.ai_analyst import analyze_with_gemini


def analyze(
    content: str,
    score: int,
    level: str,
    threat_type: str,
    indicators: list[dict[str, Any]],
    urls: list[str],
) -> AIAnalysis:
    """
    Analyse IA du message déjà scanné par le Risk Engine.
    Retourne toujours une AIAnalysis valide (jamais d'exception).
    """
    return analyze_with_gemini(content, score, level, threat_type, indicators, urls)
