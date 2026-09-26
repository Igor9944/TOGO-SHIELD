import hashlib
import os
import tempfile
from dataclasses import dataclass
from typing import BinaryIO

ALLOWED_IMAGE_EXT = frozenset({".jpg", ".jpeg", ".png", ".webp"})
ALLOWED_PDF_EXT = frozenset({".pdf"})
ALLOWED_TXT_EXT = frozenset({".txt"})
ALLOWED_EXTENSIONS = ALLOWED_IMAGE_EXT | ALLOWED_PDF_EXT | ALLOWED_TXT_EXT

MAX_SIZE_BYTES = 4 * 1024 * 1024  # 4 MB (Vercel Function body limit ~4.5 MB)

MAGIC_BYTES = {
    b"\xff\xd8\xff": {".jpg", ".jpeg"},
    b"\x89PNG\r\n\x1a\n": {".png"},
    b"RIFF": {".webp"},  # WebP starts with RIFF....WEBP
    b"%PDF": {".pdf"},
}


@dataclass(frozen=True)
class FileValidation:
    filename: str
    extension: str
    content_type: str
    size: int
    sha256: str
    kind: str  # "image", "pdf", "text"


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def detect_extension_from_magic(data: bytes) -> str | None:
    """Detect file extension from magic bytes. Returns extension or None."""
    for magic, exts in MAGIC_BYTES.items():
        if data.startswith(magic):
            return next(iter(exts))
    return None


def validate_upload(
    filename: str,
    content_type: str,
    data: bytes,
) -> FileValidation:
    """Validate an uploaded file. Raises HTTPException on failure."""
    from fastapi import HTTPException

    _, ext = os.path.splitext(filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"Extension non autorisée : {ext or '(aucune)'}. Formats autorisés : {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    if len(data) > MAX_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Fichier trop volumineux : {len(data)} octets (max {MAX_SIZE_BYTES} octets / 4 Mo)",
        )

    normalized_content_type = content_type.split(";", 1)[0].strip().lower()
    allowed_mimes = {
        ".jpg": {"image/jpeg"},
        ".jpeg": {"image/jpeg"},
        ".png": {"image/png"},
        ".webp": {"image/webp"},
        ".pdf": {"application/pdf"},
        ".txt": {"text/plain", "application/octet-stream"},
    }
    allowed = allowed_mimes.get(ext, set())
    if normalized_content_type and normalized_content_type not in allowed:
        raise HTTPException(
            status_code=415,
            detail=f"Type MIME incohérent pour {filename}: {normalized_content_type} (autorisé: {', '.join(sorted(allowed)) or 'aucun'}).",
        )

    detected_ext = detect_extension_from_magic(data)
    if detected_ext is not None and ext and detected_ext != ext:
        raise HTTPException(
            status_code=415,
            detail=f"Incohérence entre l'extension ({ext}) et le type de fichier réel (magic bytes: {detected_ext}). Rejet de sécurité.",
        )

    if ext in ALLOWED_IMAGE_EXT:
        kind = "image"
    elif ext == ".pdf":
        kind = "pdf"
    else:
        kind = "text"

    sha256 = compute_sha256(data)

    return FileValidation(
        filename=filename,
        extension=ext,
        content_type=normalized_content_type or content_type,
        size=len(data),
        sha256=sha256,
        kind=kind,
    )
