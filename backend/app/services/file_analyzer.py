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
from app.services.url_analyzer import extract_urls
from app.services.risk_engine import assess_risk
from app.services.urlhaus_service import UrlhausResult, query_urlhaus

if TYPE_CHECKING:
    from app.schemas.scan import ScanResult

logger = logging.getLogger(__name__)


def analyze_file(
    filename: str,
    content_type: str,
    data: bytes,
    ocr_text: str | None = None,
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

    if validation.kind == "image" and ocr_text is not None:
        safe_ocr_text = ocr_text.strip()[:1_000_000]
        if safe_ocr_text:
            raw_extracted.text = safe_ocr_text
            raw_extracted.urls = extract_urls(safe_ocr_text)
            raw_extracted.ocr_used = True
            raw_extracted.ocr_message = "OCR appliqué avec Tesseract.js"
            raw_extracted.extraction_method = "tesseract_js"

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
