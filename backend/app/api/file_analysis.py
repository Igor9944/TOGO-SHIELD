"""
Route API pour l'analyse de fichiers uploadés.

POST /api/analyze/file

multipart/form-data :
  - file : le fichier à analyser

Réponse : FileAnalysisResponse avec deux résultats séparés :
  - analyses.togo_shield : moteur interne
  - analyses.urlhaus : threat intelligence URLhaus
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.schemas.file_analysis import FileAnalysisResponse
from app.services.file_analyzer import analyze_file

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analyze", tags=["file-analysis"])


@router.post(
    "/file",
    response_model=FileAnalysisResponse,
    summary="Analyser un fichier uploadé",
    description="Upload un fichier (image, PDF, texte) pour analyse TOGO-SHIELD + URLhaus. "
                "Formats: JPG, JPEG, PNG, WEBP, PDF, TXT. Max 10 Mo.",
)
async def analyze_file_upload(
    file: UploadFile = File(...),
    ocr_text: str | None = Form(default=None),
    db: Session = Depends(get_db),
) -> FileAnalysisResponse:
    """
    Analyse un fichier uploadé.

    Pipeline :
    1. Validation (extension whitelist, magic bytes, taille max 10 Mo, SHA-256)
    2. Extraction (OCR pour images, texte pour PDF/TXT)
    3. Analyse TOGO-SHIELD (moteur interne)
    4. URLhaus pour chaque URL extraite (source externe indépendante)
    """
    settings = get_settings()

    # Lire le fichier
    data = await file.read()

    if not data:
        raise HTTPException(status_code=400, detail="Fichier vide")

    # Vérifier la taille (max_upload_size_mb vient des settings)
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    if len(data) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Fichier trop volumineux : {len(data)} octets (max {max_bytes} octets / {settings.max_upload_size_mb} Mo)",
        )

    # Lancer l'analyse
    try:
        result = analyze_file(
            filename=file.filename or "unknown",
            content_type=file.content_type or "application/octet-stream",
            data=data,
            ocr_text=ocr_text,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Erreur lors de l'analyse du fichier %s: %s", file.filename, exc)
        raise HTTPException(
            status_code=500,
            detail="Erreur interne lors de l'analyse du fichier",
        ) from exc

    return result
