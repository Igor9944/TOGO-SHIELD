"""
Service d'analyse IA (Google Gemini).

Fournit une explication du score et une classification fine,
APÉRÉIDREMENT sur le Risk Engine.
"""
from __future__ import annotations

import logging
import time
from typing import Any

from google import genai
from google.genai import types

from app.schemas.ai import AIAnalysis, Explanation, RiskClassification
from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Prompt système pour l'analyse de messages suspects
SYSTEM_INSTRUCTION = (
    "Tu es un expert en cybersécurité et en ingénierie sociale. "
    "Analyse le message fourni à la lumière des indicateurs de risque détectés. "
    "Réponds en FRANÇAIS. "
    "Sois précis, concis et factuel. "
    "Ne invente pas de détails. "
    "Si le message semble légitime, dit-le clairement."
)

# Maximum de caractères à envoyer au modèle ( Limitation pour économiser les tokens )
MAX_CONTENT_LENGTH = 4000


def analyze_with_gemini(
    content: str,
    score: int,
    level: str,
    threat_type: str,
    indicators: list[dict[str, Any]],
    urls: list[str],
) -> AIAnalysis:
    """
    Envoie le contenu et les indicateurs à Gemini pour obtenir :
    - Une explication du score
    - Une classification fine

    Retourne toujours une AIAnalysis valide, même en cas d'erreur.
    """
    settings = get_settings()

    # Échec rapide si non configuré
    if not settings.google_api_key:
        return AIAnalysis(
            enabled=True,
            status="not_configured",
            explanation=None,
            classification=None,
            error="GOOGLE_API_KEY non configurée",
        )

    if not content.strip():
        return AIAnalysis(
            enabled=True,
            status="not_used",
            explanation=None,
            classification=None,
        )

    # Tronquer le contenu si nécessaire
    truncated_content = content[:MAX_CONTENT_LENGTH]

    client = genai.Client(api_key=settings.google_api_key)
    start = time.monotonic()

    try:
        # Préparer les données pour le prompt
        indicators_summary = _format_indicators(indicators)
        urls_summary = _format_urls(urls)
        prompt = _build_prompt(truncated_content, score, level, threat_type, indicators_summary, urls_summary)

        # Appel Gemini avec sortie structurée (Pydantic schema via response_schema)
        response = client.models.generate_content(
            model=settings.ai_model or "gemini-3.8-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                temperature=0.2,
                top_p=0.5,
                response_mime_type="application/json",
                response_schema=AIAnalysis.model_json_schema(),
            ),
        )

        if not response or not response.text:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return AIAnalysis(
                enabled=True,
                status="unavailable",
                latency_ms=elapsed_ms,
                error="Réponse vide de Gemini",
            )

        # Parser la réponse structurée
        analysis = AIAnalysis.model_validate_json(response.text)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        analysis.latency_ms = elapsed_ms
        analysis.status = "available"
        analysis.enabled = True

        return analysis

    except Exception as exc:
        elapsed_ms = int((time.monotonic() - start) * 1000)
        logger.warning("Gemini analysis failed: %s (%d ms)", exc, elapsed_ms)
        return AIAnalysis(
            enabled=True,
            status="error",
            latency_ms=elapsed_ms,
            error=f"{type(exc).__name__}: {exc}",
        )


def _format_indicators(indicators: list[dict[str, Any]]) -> str:
    """Formate les indicateurs en texte pour le prompt."""
    if not indicators:
        return "Aucun indicateur de risque détecté."
    lines = []
    for ind in indicators:
        desc = ind.get("description", "unknown")
        weight = ind.get("weight", 0)
        lines.append(f"- {desc} (poids: {weight})")
    return "\n".join(lines)


def _format_urls(urls: list[str]) -> str:
    """Formate les URLs pour le prompt."""
    if not urls:
        return "Aucune URL détectée."
    return "\n".join(f"- {u}" for u in urls[:5])


def _build_prompt(
    content: str,
    score: int,
    level: str,
    threat_type: str,
    indicators: str,
    urls: str,
) -> str:
    """Construit le prompt pour Gemini."""
    return (
        f"### MESSAGE À ANALYSER ###\n\n{content}\n\n"
        f"### RÉSULTAT DU RISK ENGINE ###\n"
        f"Score: {score}/100\n"
        f"Niveau: {level}\n"
        f"Type de menace: {threat_type}\n\n"
        f"### INDICATEURS DÉTECTÉS ###\n{indicators}\n\n"
        f"### URLS DÉTECTÉES ###\n{urls}\n\n"
        f"### TÂCHE ###\n"
        f"1. Explique le score et la menace en français (summary)\n"
        f"2. Donne des détails techniques (details, max 5 points)\n"
        f"3. Classifie la menace (category, subcategory, tactic)\n"
        f"4. Liste les URLs concernées (affected_urls)\n"
        f"5. Confiance : ajustement mineur (-0.2 à +0.2) pour confidence_boost\n"
        f"Réponds au format JSON avec les champs: explanation (summary, details, affected_urls), "
        f"classification (category, subcategory, tactic), confidence_boost, enabled, model, status."
    )
