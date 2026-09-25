from app.schemas.scan import ScanResult, RiskLevel


def format_scan_result(result: ScanResult) -> str:
    level_label = {RiskLevel.LOW: "FAIBLE", RiskLevel.MEDIUM: "MOYEN", RiskLevel.CRITICAL: "CRITIQUE"}[result.level]
    emoji = {RiskLevel.LOW: "🟢", RiskLevel.MEDIUM: "🟠", RiskLevel.CRITICAL: "🔴"}[result.level]
    indicators = "\n".join(f"• {item.description}" for item in result.indicators) or "• Aucun indicateur majeur détecté"
    recommendations = "\n".join(f"• {item}" for item in result.recommendations)
    return f"🛡️ TOGO-SHIELD\n\n{emoji} NIVEAU : {level_label}\n📊 Score : {result.score}/100\n🎯 Type : {result.threat_type.upper()}\n\n🔎 Indicateurs détectés :\n{indicators}\n\n💡 Recommandation :\n{recommendations}"