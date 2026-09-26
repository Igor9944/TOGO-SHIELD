"""Provider Gemini pour l'analyse IA."""
from __future__ import annotations

import logging
from typing import Any

from google import genai
from google.genai import types

from app.schemas.ai import AIAnalysis, AnalysisContext

logger = logging.getLogger(__name__)


def analyze(ctx: AnalysisContext) -> AIAnalysis:
    """
    Envoie le contexte au Gemini et retourne AIAnalysis.
    Ne jamais lever d'exception — retourne un AIAnalysis avec status=error en cas d'échec.
    """
    from app.core.config import get_settings

    settings = get_settings()

    if not settings.google_api_key:
        return AIAnalysis(
            status="not_configured",
            error="GOOGLE_API_KEY non configurée",
        )

    if not settings.ai_enabled:
        return AIAnalysis(
            status="not_used",
        )

    try:
        client = genai.Client(api_key=settings.google_api_key)

        # Prompt système : expliquer le score, classifier, ne jamais contredire le Risk Engine
        system_instruction = (
            "Tu es un assistant de cybersécurité. Tu reçois les résultats d'un moteur de détection de menaces. "
            "Ton rôle : expliquer le score en français, proposer une classification de la menace, "
            "et donner un avis de sévérité. "
            "Tu ne DOIS PAS modifier le score. Tu ne DOIS PAS contredire les indicateurs détectés. "
            "Réponds en JSON strict avec les champs : explanation (summary, details, confidence), "
            "classification (category, sub_category, severity_assessment)."
        )

        # Prompt utilisateur : contexte + demande d'analyse
        user_prompt = (
            f"Score du moteur : {ctx.score}/100\n"
            f"Niveau : {ctx.level}\n"
            f"Type de menace : {ctx.threat_type}\n"
            f"Indicateurs : {ctx.indicators}\n"
            f"URLs : {ctx.urls}\n\n"
            f"Contenu analysé :\n{ctx.content}\n\n"
            f"Analyse et classification :"
        )

        response = client.models.generate_content(
            model=settings.ai_model or "gemini-3.8-flash",
            contents=[
                types.Content(
                    role="system",
                    parts=[types.Part(text=system_instruction)],
                ),
                types.Content(
                    role="user",
                    parts=[types.Part(text=user_prompt)],
                ),
            ],
            config=types.GenerateContentConfig(
                temperature=0.2,
                top_p=0.5,
                max_output_tokens=2048,
            ),
        )

        if not response or not response.text:
            return AIAnalysis(
                status="unavailable",
                error="Réponse vide de Gemini",
            )

        # Parsing du JSON de réponse
        import json
        try:
            data = json.loads(response.text)
            explanation_data = data.get("explanation", {})
            classification_data = data.get("classification", {})

            return AIAnalysis(
                explanation=AIExplanation(**explanation_data) if explanation_data else None,
                classification=AIClassification(**classification_data) if classification_data else None,
                status="available",
            )
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning("Erreur parsing réponse Gemini: %s — réponse: %s", exc, response.text[:200])
            return AIAnalysis(
                status="error",
                error=f"Parsing JSON échoué: {exc}",
            )

    except Exception as exc:
        logger.warning("Erreur Gemini: %s", exc)
        return AIAnalysis(
            status="error",
            error=f"{type(exc).__name__}: {exc}",
        )
