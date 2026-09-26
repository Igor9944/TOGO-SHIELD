import re

from app.schemas.scan import Indicator, RiskLevel, ScanResult, ScoreBreakdown
from app.services.url_analyzer import analyze_urls
from app.threat_intelligence import inspect_url


RULES = (
    ("sensitive_data", "Demande d'OTP ou de code secret", 30, r"\b(otp|code secret|mot de passe|password|pin|identifiant)\b"),
    ("urgency", "Pression temporelle", 20, r"\b(urgent|immédiatement|maintenant|suspendu|bloqué|dernière chance)\b"),
    ("finance", "Référence à un service financier ou Mobile Money", 15, r"\b(mobile money|tmoney|flooz|fcfa|paiement|transfert|argent)\b"),
    ("impersonation", "Usurpation possible d'un service officiel", 10, r"\b(banque|service client|support|administrateur|agent)\b"),
    ("social_engineering", "Promesse ou sollicitation sociale", 10, r"\b(félicitations|gagné|cadeau|concours|emploi|recrutement)\b"),
)


def assess_risk(
    content: str,
    source: str = "web",
    *,
    include_external_intel: bool = True,
) -> ScanResult:
    """
    Analyse le contenu.

    include_external_intel=False est utilisé par l'analyse de fichiers afin que
    TOGO-SHIELD reste un moteur local indépendant et que URLhaus ne soit appelé
    qu'une seule fois par URL par le pipeline fichier.
    """
    normalized = content.casefold()
    indicators: list[Indicator] = []
    breakdown: list[ScoreBreakdown] = []
    intelligence = []
    score = 0

    for indicator_type, description, weight, pattern in RULES:
        if re.search(pattern, normalized):
            indicators.append(Indicator(type=indicator_type, description=description, weight=weight))
            score += weight
            breakdown.append(ScoreBreakdown(source="Local analysis", weight=weight))

    urls, findings = analyze_urls(content)
    for finding in findings:
        for indicator_type, description, weight in finding.indicators:
            indicators.append(Indicator(type=indicator_type, description=description, weight=weight))
            score += weight
        if include_external_intel:
            provider_results = inspect_url(finding.url)
            intelligence.extend(provider_results)
            for provider_result in provider_results:
                if provider_result.malicious:
                    weight = 35 if provider_result.provider == "VirusTotal" else 25
                    indicators.append(Indicator(
                        type="reputation",
                        description=f"{provider_result.provider} signale cette URL comme menace",
                        weight=weight,
                    ))
                    score += weight
                    breakdown.append(ScoreBreakdown(source=provider_result.provider, weight=weight))

    if urls:
        indicators.append(Indicator(type="url", description="Présence d'un lien externe", weight=10))
        score += 10
        breakdown.append(ScoreBreakdown(source="Local URL analysis", weight=10))

    score = min(score, 100)
    level = RiskLevel.CRITICAL if score >= 70 else RiskLevel.MEDIUM if score >= 40 else RiskLevel.LOW
    threat_type = (
        "phishing"
        if any(item.type in {"sensitive_data", "impersonation", "url", "reputation"} for item in indicators)
        else "suspicious" if indicators else "low risk"
    )
    recommendations = (
        ["Ne cliquez pas sur les liens suspects.", "Ne communiquez jamais votre OTP, PIN ou mot de passe.", "Vérifiez directement auprès du service officiel."]
        if indicators
        else ["Aucun indicateur majeur détecté. Restez néanmoins vigilant."]
    )
    confidence = min(0.99, 0.45 + min(len(indicators), 5) * 0.1) if indicators else 0.25

    return ScanResult(
        score=score,
        level=level,
        threat_type=threat_type,
        indicators=indicators,
        recommendations=recommendations,
        urls=urls,
        confidence=confidence,
        score_breakdown=breakdown,
        threat_intelligence=intelligence,
        source=source,
    )
