import base64

import httpx

from app.core.config import get_settings
from app.schemas.scan import ProviderResult


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def inspect(url: str) -> ProviderResult:
    settings = get_settings()
    if not settings.virustotal_api_key:
        return ProviderResult(provider="VirusTotal")
    try:
        response = httpx.get(f"https://www.virustotal.com/api/v3/urls/{_url_id(url)}", headers={"x-apikey": settings.virustotal_api_key}, timeout=5)
        if response.status_code == 404:
            return ProviderResult(provider="VirusTotal", status="not_found")
        response.raise_for_status()
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(value) for value in stats.values())
        detections = malicious + suspicious
        return ProviderResult(provider="VirusTotal", known=True, malicious=malicious > 0, detections=detections, total_engines=total, confidence=min(detections / total, 1) if total else 0, evidence=[f"{malicious} moteur(s) malveillant(s)", f"{suspicious} moteur(s) suspect(s)"], status="available")
    except (httpx.HTTPError, ValueError, TypeError):
        return ProviderResult(provider="VirusTotal", status="unavailable")