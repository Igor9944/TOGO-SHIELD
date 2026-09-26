"""
Service d'extraction de contenu pour fichiers uploadés.

Supporte :
- Images (JPEG, PNG, WEBP) → OCR avec Tesseract local ou fallback Tesseract.js/Vercel
- PDF → extraction texte avec les bibliothèques disponibles
- TXT → lecture directe
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from io import BytesIO

import httpx

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
    """Extrait le texte et les URLs d'un fichier selon son type."""
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
            # Tesseract.js ne gère pas directement les PDF : le PDF doit
            # d'abord être rasterisé. On conserve donc ici le comportement
            # précédent et n'utilise le fallback OCR que pour les images.
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

    Stratégie :
    1. Tesseract système local (développement / environnement complet).
    2. Fallback HTTP vers Tesseract.js sur Vercel si le binaire système
       n'existe pas dans le runtime serverless.
    """
    try:
        from PIL import Image
        import pytesseract

        image = Image.open(BytesIO(data))
        if image.mode in ("RGBA", "P", "LA"):
            image = image.convert("RGB")

        text = pytesseract.image_to_string(image).strip()
        if text:
            return (text, True, None)

        # Le binaire peut être installé mais ne pas disposer des données
        # linguistiques attendues : on tente quand même le fallback distant.
        local_error = "Tesseract local n'a retourné aucun texte"
    except ImportError:
        local_error = "Pillow/pytesseract non installé"
    except Exception as exc:
        local_error = f"OCR local indisponible ({type(exc).__name__})"

    remote_text, remote_error = _ocr_remote(data)
    if remote_text:
        return (remote_text, True, None)

    return (
        "",
        False,
        remote_error or local_error,
    )


def _ocr_remote(data: bytes) -> tuple[str, str | None]:
    """Utilise l'endpoint Tesseract.js du même déploiement Vercel."""
    service_url = os.getenv("OCR_SERVICE_URL")
    if not service_url and os.getenv("VERCEL") == "1":
        deployment_url = os.getenv("VERCEL_URL")
        if deployment_url:
            service_url = f"https://{deployment_url}/api/ocr"

    if not service_url:
        return "", None

    try:
        response = httpx.post(
            service_url,
            content=data,
            headers={"content-type": "application/octet-stream"},
            timeout=45.0,
        )
        response.raise_for_status()
        payload = response.json()
        text = str(payload.get("text") or "").strip()
        if text:
            return text, None
        return "", "OCR distant n'a retourné aucun texte"
    except httpx.TimeoutException:
        return "", "OCR distant timeout"
    except httpx.HTTPStatusError as exc:
        return "", f"OCR distant HTTP {exc.response.status_code}"
    except Exception as exc:
        return "", f"OCR distant indisponible ({type(exc).__name__})"


# ─── PDF ──────────────────────────────────────────────────────────────

def _extract_pdf_text(data: bytes, filename: str) -> tuple[str, bool]:
    """Extrait le texte d'un PDF. Retourne (text, ocr_needed)."""
    text = ""
    ocr_needed = False

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

    try:
        from pdfminer.high_level import extract_text

        text = extract_text(BytesIO(data))
        if not text.strip():
            ocr_needed = True
        return (text, ocr_needed)
    except ImportError:
        pass

    text = _extract_pdf_text_from_stream(data)
    if text.strip():
        return (text, False)

    return ("", True)


def _extract_pdf_text_from_stream(data: bytes) -> str:
    """Parse un flux PDF simple pour récupérer du texte visible."""
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


# ─── TEXT ─────────────────────────────────────────────────────────────

def _decode_text(data: bytes, filename: str) -> str:
    """Décodage tolerant pour fichiers texte."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass

    try:
        return data.decode("latin-1")
    except Exception:
        return ""


# ─── URL EXTRACTION ───────────────────────────────────────────────────

def _extract_urls(text: str) -> list[str]:
    """Extrait les URLs uniques depuis du texte."""
    if not text:
        return []

    urls: set[str] = set()
    seen: set[str] = set()

    for match in URL_PATTERN.finditer(text):
        url = match.group(0).rstrip(".,!?;:)\"'")
        if url and url not in seen:
            seen.add(url)
            urls.add(url)

    for match in MARKDOWN_LINK_PATTERN.finditer(text):
        link_url = match.group(2).strip().rstrip(".,!?;:)\"'")
        if link_url and link_url not in seen:
            seen.add(link_url)
            urls.add(link_url)

    return sorted(urls)
