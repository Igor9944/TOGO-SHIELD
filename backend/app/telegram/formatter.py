from app.schemas.file_analysis import FileAnalysisResponse
from app.schemas.scan import ScanResult, RiskLevel


def format_scan_result(result: ScanResult) -> str:
    level_label = {RiskLevel.LOW: "FAIBLE", RiskLevel.MEDIUM: "MOYEN", RiskLevel.CRITICAL: "CRITIQUE"}[result.level]
    emoji = {RiskLevel.LOW: "🟢", RiskLevel.MEDIUM: "🟠", RiskLevel.CRITICAL: "🔴"}[result.level]
    indicators = "\n".join(f"• {item.description}" for item in result.indicators) or "• Aucun indicateur majeur détecté"
    recommendations = "\n".join(f"• {item}" for item in result.recommendations)
    return f"🛡️ TOGO-SHIELD\n\n{emoji} NIVEAU : {level_label}\n📊 Score : {result.score}/100\n🎯 Type : {result.threat_type.upper()}\n\n🔎 Indicateurs détectés :\n{indicators}\n\n💡 Recommandation :\n{recommendations}"

def format_file_analysis(result: FileAnalysisResponse) -> str:
    togo = result.analyses.togo_shield
    if togo is None:
        return (
            "🛡️ TOGO-SHIELD\n\n"
            f"📄 Fichier : {result.file.filename}\n"
            "⚠️ Aucun contenu exploitable n'a été détecté."
        )

    level_map = {"low": ("FAIBLE", "🟢"), "medium": ("MOYEN", "🟠"), "critical": ("CRITIQUE", "🔴")}
    level_label, emoji = level_map.get(togo.risk_level, (togo.risk_level.upper(), "⚪"))
    indicators = "\n".join(f"• {item.description}" for item in togo.indicators) or "• Aucun indicateur majeur détecté"
    urls = result.extracted_content.urls
    urlhaus_hits = [item for item in result.analyses.urlhaus if item.found]
    recommendations = "\n".join(f"• {item}" for item in togo.recommendations[:3])

    lines = [
        "🛡️ TOGO-SHIELD",
        "",
        f"📄 Fichier : {result.file.filename}",
        f"{emoji} NIVEAU : {level_label}",
        f"📊 Score : {togo.score}/100",
        f"🎯 Type : {togo.threat_type.upper()}",
        "",
        "🔎 Indicateurs détectés :",
        indicators,
        "",
        f"🔗 URL détectées : {len(urls)}",
        f"🌐 URLhaus : {len(urlhaus_hits)} menace(s) détectée(s)",
    ]

    if result.extracted_content.ocr_used:
        lines.append("📝 OCR : texte extrait de l'image")
    elif result.extracted_content.ocr_message:
        lines.append(f"📝 Extraction : {result.extracted_content.ocr_message}")

    if recommendations:
        lines.extend(["", "💡 Recommandations :", recommendations])

    return "\n".join(lines)
