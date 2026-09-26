"""
Service principal d'analyse de fichier.

Orchestrateur : validation → extraction → analyse TOGO-SHIELD locale → URLhaus.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.schemas.file_analysis import (
    ExtractedContent,
    FileAnalysisResponse,
    FileAnalyses,
    FileInfo,
    TogoShieldAnalysis,
    UrlhausAnalysis,
)
from app.services.file_validation import validate_upload
from app.services.file_extractor import extract_text_from_data
from app.services.risk_engine import assess_risk
from app.services.urlhaus_service import UrlhausResult, query_urlhaus
from app.models.scan import ScanRecord
import json
from sqlalchemy.orm import Session

if TYPE_CHECKING:
    from app.schemas.scan import ScanResult

logger = logging.getLogger(__name__)


def analyze_file(
    filename: str,
    content_type: str,
    data: bytes,
) -> FileAnalysisResponse:
    """
    Analyse complète d'un fichier.

    TOGO-SHIELD est volontairement exécuté en mode local-only. URLhaus est
    appelé séparément, exactement une fois par URL normalisée.
    """
    validation = validate_upload(filename, content_type, data)
    file_info = FileInfo(
        filename=validation.filename,
        type=validation.content_type or validation.extension,
        size=validation.size,
        sha256=validation.sha256,
    )

    raw_extracted = extract_text_from_data(data, validation.kind, filename)
    extracted_content = ExtractedContent(
        text=raw_extracted.text,
        urls=raw_extracted.urls,
        ocr_used=raw_extracted.ocr_used,
        ocr_message=raw_extracted.ocr_message,
        extraction_method=raw_extracted.extraction_method,
    )

    if extracted_content.text:
        scan_result: ScanResult = assess_risk(
            extracted_content.text,
            source="file",
            include_external_intel=False,
        )
        togo_shield = TogoShieldAnalysis.from_scan_result(scan_result, from_file=True)
    else:
        togo_shield = TogoShieldAnalysis(
            engine="togo_shield",
            score=0,
            risk_level="low",
            threat_type="low risk",
            confidence=0.0,
            indicators=[],
            recommendations=["Aucun contenu exploitable trouvé dans le fichier."],
            reasons=["Aucun texte ou URL extractible."],
        )

    urlhaus_results: list[UrlhausAnalysis] = []
    for url in extracted_content.urls:
        url_result: UrlhausResult = query_urlhaus(url)
        urlhaus_results.append(
            UrlhausAnalysis(
                source=url_result.source,
                url=url_result.url,
                found=url_result.found,
                url_status=url_result.url_status,
                threat=url_result.threat,
                threat_type=url_result.threat_type,
                date_added=url_result.date_added,
                danger_level=url_result.danger_level,
                tags=list(url_result.tags) if url_result.tags else [],
                status=url_result.status,
                error=url_result.error,
            )
        )

    return FileAnalysisResponse(
        file=file_info,
        extracted_content=extracted_content,
        analyses=FileAnalyses(
            togo_shield=togo_shield,
            urlhaus=urlhaus_results,
        ),
    )



def persist_file_analysis(
    result: FileAnalysisResponse,
    db: Session,
    *,
    source: str = "file",
    telegram: dict[str, int] | None = None,
) -> int:
    """Persist a completed file analysis and return the scan id."""
    togo = result.analyses.togo_shield
    record = ScanRecord(
        source=source,
        content=result.extracted_content.text,
        score=togo.score if togo else 0,
        level=togo.risk_level if togo else "low",
        threat_type=togo.threat_type if togo else "low risk",
        confidence=round((togo.confidence if togo else 0.0) * 100),
        telegram_chat_id=telegram.get("chat_id") if telegram else None,
        telegram_user_id=telegram.get("user_id") if telegram else None,
        telegram_message_id=(telegram.get("message_id") or None) if telegram else None,
        media_type=result.file.type,
        file_name=result.file.filename,
        file_type=result.file.type,
        file_size=result.file.size,
        file_sha256=result.file.sha256,
        extracted_text=result.extracted_content.text,
        indicators_json=json.dumps(
            [item.model_dump() for item in (togo.indicators if togo else [])],
            ensure_ascii=False,
        ),
        threat_intelligence_json=json.dumps(
            [item.model_dump() for item in result.analyses.urlhaus],
            ensure_ascii=False,
        ),
        score_breakdown_json=json.dumps(
            togo.score_breakdown if togo else [],
            ensure_ascii=False,
        ),
    )
    try:
        db.add(record)
        db.commit()
        db.refresh(record)
        result.scan_id = record.id
        return record.id
    except Exception:
        db.rollback()
        raise
