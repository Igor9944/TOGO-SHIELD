"""
Route API pour l'analyse de fichiers uploadés.

POST /api/analyze/file
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.scan import ScanRecord
from app.schemas.file_analysis import FileAnalysisResponse
from app.services.file_analyzer import analyze_file

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analyze", tags=["file-analysis"])


@router.post(
    "/file",
    response_model=FileAnalysisResponse,
    summary="Analyser un fichier uploadé",
    description=(
        "Upload un fichier (image, PDF, texte) pour analyse TOGO-SHIELD + URLhaus. "
        "Formats: JPG, JPEG, PNG, WEBP, PDF, TXT. Max 4 Mo."
    ),
)
async def analyze_file_upload(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> FileAnalysisResponse:
    """Valide, extrait, analyse et persiste un scan de fichier."""
    settings = get_settings()
    max_bytes = settings.max_upload_size_mb * 1024 * 1024

    # Lire au maximum max+1 : un fichier trop gros ne peut pas consommer
    # arbitrairement la mémoire du worker avant d'être rejeté.
    data = await file.read(max_bytes + 1)

    if not data:
        raise HTTPException(status_code=400, detail="Fichier vide")

    if len(data) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=(
                f"Fichier trop volumineux : {len(data)} octets "
                f"(max {max_bytes} octets / {settings.max_upload_size_mb} Mo)"
            ),
        )

    try:
        result = analyze_file(
            filename=file.filename or "unknown",
            content_type=file.content_type or "application/octet-stream",
            data=data,
        )

        togo = result.analyses.togo_shield
        record = ScanRecord(
            source="file",
            content=result.extracted_content.text,
            score=togo.score if togo else 0,
            level=togo.risk_level if togo else "low",
            threat_type=togo.threat_type if togo else "low risk",
            confidence=round((togo.confidence if togo else 0.0) * 100),
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
        db.add(record)
        db.commit()
        db.refresh(record)
        result.scan_id = record.id
        return result

    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.exception("Erreur lors de l'analyse/persistance du fichier %s: %s", file.filename, exc)
        raise HTTPException(
            status_code=500,
            detail="Erreur interne lors de l'analyse du fichier",
        ) from exc
