"""
Service d'extraction de contenu pour fichiers uploadés.

Supporte :
- Images (JPEG, PNG, WEBP) → OCR avec Tesseract
- PDF → extraction texte (PyPDF2/pdfplumber si dispo, sinon OCR)
- TXT → lecture directe
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from io import BytesIO
from typing import Optional

URL_PATTERN = re.compile(r"https?://[^\s<>)\]]+", re.IGNORECASE)
MARKDOWN_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


@dataclass
class ExtractedContent:
    """Résultat de l'extraction de contenu depuis un fichier."""
    text: str
    urls: list[str]
    ocr_used: bool = False
    ocr_message: str | None = None
    extraction_method: str = "unknown"


def extract_text_from_data(data: bytes, kind: str, filename: str) -> ExtractedContent:
    """
    Extrait le texte et les URLs d'un fichier selon son type.

    Args:
        data: octets du fichier
        kind: "image", "pdf", ou "text"
        filename: nom du fichier (pour extension)

    Returns:
        ExtractedContent avec texte, URLs, et métadonnées
    """
    urls: list[str] = []
    text = ""
    ocr_used = False
    ocr_message: str | None = None
    extraction_method = "unknown"

    if kind == "image":
        extraction_method = "ocr"
        text, ocr_used, ocr_message = _ocr_image(data)
        urls = _extract_urls(text)

    elif kind == "pdf":
        extraction_method = "pdf_text"
        text, ocr_needed = _extract_pdf_text(data, filename)
        if ocr_needed:
            ocr_message = "PDF scanné — OCR appliqué"
            ocr_used = True
            extraction_method = "pdf_ocr"
            text_from_ocr, _, _ = _ocr_image(data)
            if text_from_ocr:
                text = text + "\n\n" + text_from_ocr if text else text_from_ocr
        urls = _extract_urls(text)

    elif kind == "text":
        extraction_method = "raw_text"
        text = _decode_text(data, filename)
        urls = _extract_urls(text)

    return ExtractedContent(
        text=text.strip(),
        urls=urls,
        ocr_used=ocr_used,
        ocr_message=ocr_message,
        extraction_method=extraction_method,
    )


# ─── OCR ───────────────────────────────────────────────────────────────

def _ocr_image(data: bytes) -> tuple[str, bool, str | None]:
    """
    Lance l'OCR sur une image.

    Returns: (text, ocr_available, message_erreur)
    """
    try:
        from PIL import Image
        import pytesseract

        image = Image.open(BytesIO(data))
        # Convertir en RGB si nécessaire (transparence, etc.)
        if image.mode in ("RGBA", "P", "LA"):
            image = image.convert("RGB")
        text = pytesseract.image_to_string(image).strip()
        return (text, True, None)
    except ImportError:
        return ("", False, "OCR unavailable (Pillow/pytesseract not installed)")
    except Exception as exc:
        return ("", False, f"OCR error: {type(exc).__name__}")


# ─── PDF ───────────────────────────────────────────────────────────────

def _extract_pdf_text(data: bytes, filename: str) -> tuple[str, bool]:
    """
    Extrait le texte d'un PDF.

    Returns: (text, ocr_needed)
    - ocr_needed=True si le PDF semble scanné (pas de texte extrait)
    """
    text = ""
    ocr_needed = False

    # Essayer pdfplumber d'abord (meilleur pour le texte)
    try:
        import pdfplumber

        with pdfplumber.open(BytesIO(data)) as pdf:
            pages_text = []
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    pages_text.append(page_text)
            text = "\n\n".join(pages_text)
            if not text.strip():
                ocr_needed = True
        return (text, ocr_needed)
    except ImportError:
        pass

    # Fallback: PyPDF2
    try:
        from PyPDF2 import PdfReader

        reader = PdfReader(BytesIO(data))
        pages_text = []
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                pages_text.append(page_text)
        text = "\n\n".join(pages_text)
        if not text.strip():
            ocr_needed = True
        return (text, ocr_needed)
    except ImportError:
        pass

    # Fallback: pikepdf + pdfminer
    try:
        from pdfminer.high_level import extract_text

        text = extract_text(BytesIO(data))
        if not text.strip():
            ocr_needed = True
        return (text, ocr_needed)
    except ImportError:
        pass

    # Fallback sans dépendances PDF: extraire le contenu textuel brut des streams PDF.
    text = _extract_pdf_text_from_stream(data)
    if text.strip():
        return (text, False)

    # Aucun extracteur PDF disponible
    return ("", True)


def _extract_pdf_text_from_stream(data: bytes) -> str:
    """Parse a simple PDF byte stream to recover visible text without external libraries."""
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

    if not candidates:
        return ""

    return "\n\n".join(candidates)


# ─── TEXT ──────────────────────────────────────────────────────────────

def _decode_text(data: bytes, filename: str) -> str:
    """Décodage tolerant pour fichiers texte."""
    # Essayer UTF-8 d'abord
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass

    # Fallback: latin-1 (jamais d'erreur)
    try:
        return data.decode("latin-1")
    except Exception:
        return ""


# ─── URL EXTRACTION ────────────────────────────────────────────────────

def _extract_urls(text: str) -> list[str]:
    """Extrait les URLs uniques depuis du texte.

    Gère :
    - https://example.com
    - http://example.com
    - [texte](https://example.com)  (Markdown)
    - [https://example.com](url)    (Markdown inversé)
    - www.example.com
    """
    if not text:
        return []

    urls: set[str] = set()
    seen: set[str] = set()

    # 1. Extraire les URLs directes
    for match in URL_PATTERN.finditer(text):
        url = match.group(0).rstrip(".,!?;:)\"')")
        if url and url not in seen:
            seen.add(url)
            urls.add(url)

    # 2. Extraire les URLs cachées dans du Markdown [texte](url)
    for match in MARKDOWN_LINK_PATTERN.finditer(text):
        link_url = match.group(2).strip().rstrip(".,!?;:)\"')")
        if link_url and link_url not in seen:
            seen.add(link_url)
            urls.add(link_url)

    return sorted(urls)