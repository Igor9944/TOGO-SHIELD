"""
Service d'extraction de contenu pour fichiers uploadés.

Supporte :
- Images (JPEG, PNG, WEBP) → OCR avec Tesseract
- PDF → extraction de texte avec pypdf, sans faux statut OCR
- TXT → lecture directe

Les URLs sont normalisées via le même extracteur que le moteur d'analyse.
"""
from __future__ import annotations

import re
import os
from dataclasses import dataclass
from io import BytesIO

from app.services.url_analyzer import extract_urls


@dataclass
class ExtractedContent:
    """Résultat de l'extraction de contenu depuis un fichier."""
    text: str
    urls: list[str]
    ocr_used: bool = False
    ocr_message: str | None = None
    extraction_method: str = "unknown"


def extract_text_from_data(data: bytes, kind: str, filename: str) -> ExtractedContent:
    urls: list[str] = []
    text = ""
    ocr_used = False
    ocr_message: str | None = None
    extraction_method = "unknown"

    if kind == "image":
        extraction_method = "ocr"
        text, ocr_used, ocr_message = _ocr_image(data)
        urls = extract_urls(text)

    elif kind == "pdf":
        extraction_method = "pdf_text"
        text = _extract_pdf_text(data)
        if not text.strip():
            # Ne jamais annoncer un OCR réellement effectué si le runtime ne
            # dispose pas d'un renderer PDF + Tesseract. Le PDF reste analysable
            # dès qu'il contient du texte sélectionnable.
            ocr_message = "PDF scanné ou sans couche texte : OCR PDF non disponible sur ce runtime."
        urls = extract_urls(text)

    elif kind == "text":
        extraction_method = "raw_text"
        text = _decode_text(data, filename)
        urls = extract_urls(text)

    return ExtractedContent(
        text=text.strip(),
        urls=urls,
        ocr_used=ocr_used,
        ocr_message=ocr_message,
        extraction_method=extraction_method,
    )


def _ocr_image(data: bytes) -> tuple[str, bool, str | None]:
    """Lance l'OCR sur une image. Returns (text, ocr_used, message)."""
    try:
        from PIL import Image
        import pytesseract
        import tesseract_bin

        pytesseract.pytesseract.tesseract_cmd = tesseract_bin.TESSERACT_PATH
        os.environ.setdefault("TESSDATA_PREFIX", tesseract_bin.TESSDATA_PREFIX)

        image = Image.open(BytesIO(data))
        if image.mode in ("RGBA", "P", "LA"):
            image = image.convert("RGB")
        text = pytesseract.image_to_string(image).strip()
        return (text, True, None)
    except ImportError:
        return ("", False, "OCR unavailable (Pillow/pytesseract not installed)")
    except Exception as exc:
        return ("", False, f"OCR error: {type(exc).__name__}")


def _extract_pdf_text(data: bytes) -> str:
    """Extrait le texte sélectionnable d'un PDF."""
    try:
        from pypdf import PdfReader

        reader = PdfReader(BytesIO(data))
        pages_text = []
        for page in reader.pages:
            page_text = page.extract_text() or ""
            if page_text.strip():
                pages_text.append(page_text)
        return "\n\n".join(pages_text)
    except Exception:
        # Fallback volontairement limité : certains PDFs simples contiennent
        # encore des chaînes lisibles dans leurs streams.
        return _extract_pdf_text_from_stream(data)


def _extract_pdf_text_from_stream(data: bytes) -> str:
    try:
        decoded = data.decode("latin-1", errors="ignore")
    except Exception:
        return ""

    candidates = []
    pattern = re.compile(r"\((?:\\.|[^()\\])*\)", re.DOTALL)
    for match in pattern.finditer(decoded):
        literal = match.group(0)[1:-1]
        literal = literal.replace("\\(", "(").replace("\\)", ")")
        literal = literal.replace("\\n", "\n").replace("\\r", "\n").replace("\\t", " ")
        literal = literal.replace("\\040", " ").replace("\\055", "-")
        literal = re.sub(r"\\([0-7]{1,3})", lambda m: chr(int(m.group(1), 8)), literal)
        literal = literal.replace("\\/", "/")
        if literal.strip():
            candidates.append(literal)

    return "\n\n".join(candidates)


def _decode_text(data: bytes, filename: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")
