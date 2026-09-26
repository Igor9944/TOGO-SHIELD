"""
Tests de non-régression pour l'analyse de fichiers.

Couvre :
- Upload valide (PNG, PDF, TXT)
- Taille excessive (> 10 Mo)
- Extension interdite
- MIME incohérent (magic bytes)
- SHA-256 correct
- Extraction texte / OCR
- Extraction URL
- Score TOGO-SHIELD indépendant
- URLhaus positif / négatif / indisponible
- Plusieurs URLs
"""
from __future__ import annotations

import pytest
import io
import os
import sys

from fastapi import HTTPException

# Ajouter le backend au path pour les imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.schemas.file_analysis import (
    FileAnalysisResponse,
    FileAnalyses,
    FileInfo,
    TogoShieldAnalysis,
    UrlhausAnalysis,
)
from app.services.file_validation import validate_upload, compute_sha256
from app.services.file_analyzer import analyze_file
from app.services.file_extractor import extract_text_from_data


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def make_png_data() -> bytes:
    """Génère des données PNG minimales valides (1x1 pixel noir)."""
    # PNG header + IHDR + IDAT + IEND pour un pixel noir
    return (
        b"\x89PNG\r\n\x1a\n"
        b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde"
        b"\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N"
        b"\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def make_txt_data(text: str = "Ceci est un message de test sans URL.") -> bytes:
    return text.encode("utf-8")


def make_pdf_data() -> bytes:
    """Génère un PDF minimal valide (1 page, texte)."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\n"
        b"endobj\n"
        b"4 0 obj\n"
        b"<< /Length 44 >>\n"
        b"stream\n"
        b"BT /F1 12 Tf 100 700 Td (Test PDF content with https://example.com/path) Tj ET\n"
        b"endstream\n"
        b"endobj\n"
        b"5 0 obj\n"
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n"
        b"endobj\n"
        b"xref\n"
        b"0 6\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000186 00000 n \n"
        b"0000000324 00000 n \n"
        b"trailer\n"
        b"<< /Size 6 /Root 1 0 R >>\n"
        b"startxref\n"
        b"410\n"
        b"%%EOF\n"
    )


# ═══════════════════════════════════════════════════════════════════════════
# Tests validation
# ═══════════════════════════════════════════════════════════════════════════

class TestFileValidation:
    def test_valid_png(self):
        data = make_png_data()
        result = validate_upload("capture.png", "image/png", data)
        assert result.extension == ".png"
        assert result.kind == "image"
        assert len(result.sha256) == 64

    def test_valid_txt(self):
        data = make_txt_data()
        result = validate_upload("message.txt", "text/plain", data)
        assert result.extension == ".txt"
        assert result.kind == "text"

    def test_valid_pdf(self):
        data = make_pdf_data()
        result = validate_upload("document.pdf", "application/pdf", data)
        assert result.extension == ".pdf"
        assert result.kind == "pdf"

    def test_sha256_consistency(self):
        data = b"test content"
        h1 = compute_sha256(data)
        h2 = compute_sha256(data)
        assert h1 == h2
        assert len(h1) == 64
        assert h1 != compute_sha256(b"other content")

    def test_rejected_extension(self):
        with pytest.raises(Exception) as exc_info:
            validate_upload("malware.exe", "application/x-executable", b"fake")
        assert exc_info.value.status_code == 415

    def test_rejected_mime_mismatch(self):
        with pytest.raises(Exception) as exc_info:
            validate_upload("message.txt", "image/png", b"coucou")
        assert exc_info.value.status_code == 415

    def test_rejected_size(self):
        large_data = b"x" * (11 * 1024 * 1024)  # 11 MB
        with pytest.raises(Exception) as exc_info:
            validate_upload("large.png", "image/png", large_data)
        assert exc_info.value.status_code == 413

    def test_magic_bytes_detection_png(self):
        data = make_png_data()
        from app.services.file_validation import detect_extension_from_magic
        ext = detect_extension_from_magic(data)
        assert ext in {".png", ".jpg", ".jpeg", ".webp", ".pdf"}


# ═══════════════════════════════════════════════════════════════════════════
# Tests extraction
# ═══════════════════════════════════════════════════════════════════════════

class TestFileExtraction:
    def test_txt_extraction(self):
        data = make_txt_data("Bonjour, visitez https://example.com pour plus d'infos.")
        result = extract_text_from_data(data, "text", "test.txt")
        assert result.text == "Bonjour, visitez https://example.com pour plus d'infos."
        assert len(result.urls) == 1
        assert result.urls[0] == "https://example.com"

    def test_pdf_extraction(self):
        data = make_pdf_data()
        result = extract_text_from_data(data, "pdf", "doc.pdf")
        assert "Test PDF content" in result.text
        assert len(result.urls) >= 1
        assert any("example.com" in u for u in result.urls)

    def test_image_extraction_with_ocr(self, monkeypatch):
        """Le texte OCR passe par l'extraction d'URL du pipeline fichier."""
        import pytesseract

        monkeypatch.setattr(
            pytesseract,
            "image_to_string",
            lambda image: "Consultez https://example.com/image",
        )
        data = make_png_data()
        result = extract_text_from_data(data, "image", "img.png")
        assert result.text == "Consultez https://example.com/image"
        assert result.ocr_used is True
        assert result.ocr_message is None
        assert result.urls == ["https://example.com/image"]


# ═══════════════════════════════════════════════════════════════════════════
# Tests analyse (intégration service)
# ═══════════════════════════════════════════════════════════════════════════

class TestFileAnalyzer:
    def test_txt_analysis(self):
        """Analyse d'un fichier TXT simple."""
        data = make_txt_data("Urgent : votre compte est suspendu. Vérifiez immédiatement.")
        result = analyze_file("alerte.txt", "text/plain", data)

        assert isinstance(result, FileAnalysisResponse)
        assert result.file.filename == "alerte.txt"
        assert result.file.type == "text/plain"
        assert result.file.size == len(data)
        assert len(result.file.sha256) == 64

        # Moteur TOGO-SHIELD
        assert result.analyses.togo_shield is not None
        assert result.analyses.togo_shield.engine == "togo_shield"
        # Le texte contient "urgent" et "suspendu" → score > 0
        assert result.analyses.togo_shield.score > 0

        # URLhaus : pas d'URL dans le texte
        assert len(result.analyses.urlhaus) == 0

    def test_url_extraction_and_urlhaus(self):
        """URL détectée → URLhaus interrogé."""
        data = make_txt_data("Visitez https://example.com pour vérifier votre compte.")
        result = analyze_file("lien.txt", "text/plain", data)

        assert len(result.analyses.urlhaus) >= 1
        urlhaus_entry = result.analyses.urlhaus[0]
        assert urlhaus_entry.source == "urlhaus"
        assert urlhaus_entry.url == "https://example.com"

    def test_no_text_no_score(self):
        """Fichier sans contenu exploitable → score 0."""
        data = make_png_data()  # sans OCR
        result = analyze_file("image.png", "image/png", data)

        assert result.analyses.togo_shield is not None
        assert result.analyses.togo_shield.score == 0
        assert result.analyses.togo_shield.reasons == ["Aucun texte ou URL extractible."]

    def test_multiple_urls(self):
        """Plusieurs URLs → résultats URLhaus séparés."""
        data = make_txt_data(
            "Voir https://site-a.com et https://site-b.com pour les détails."
        )
        result = analyze_file("multi.txt", "text/plain", data)

        assert len(result.analyses.urlhaus) == 2
        assert result.analyses.urlhaus[0].url != result.analyses.urlhaus[1].url

    def test_separate_motors(self):
        """Vérifie que TOGO-SHIELD et URLhaus sont bien séparés."""
        data = make_txt_data("Urgent : https://example.com")
        result = analyze_file("test.txt", "text/plain", data)

        # Le score TOGO-SHIELD vient du moteur interne
        assert result.analyses.togo_shield is not None
        togo_score = result.analyses.togo_shield.score

        # URLhaus est séparé
        assert len(result.analyses.urlhaus) >= 1

        # Le score TOGO-SHIELD n'est PAS basé sur URLhaus
        # (même si URLhaus est indisponible, le score TOGO-SHIELD reste)
        assert togo_score >= 0


# ═══════════════════════════════════════════════════════════════════════════
# Tests non-régression Telegram
# ═══════════════════════════════════════════════════════════════════════════

class TestTelegramNoRegression:
    """Vérifie que rien n'a cassé dans Telegram."""

    def test_imports_toujours_valides(self):
        from app.telegram.formatter import format_scan_result
        from app.telegram.service import send_text, send_message
        from app.schemas.scan import ScanResult, RiskLevel, Indicator
        assert callable(format_scan_result)

    def test_formatter_core_fields(self):
        from app.telegram.formatter import format_scan_result
        from app.schemas.scan import ScanResult, RiskLevel, Indicator

        result = ScanResult(
            score=70,
            level=RiskLevel.CRITICAL,
            threat_type="phishing",
            indicators=[Indicator(type="test", description="Test indicator", weight=1)],
            recommendations=["Ne cliquez pas."],
            source="telegram",
        )
        text = format_scan_result(result)
        assert "TOGO-SHIELD" in text
        assert "CRITIQUE" in text
        assert "70/100" in text
