import httpx

from app.core.config import get_settings
from app.schemas.scan import ProviderResult


def inspect(url: str) -> ProviderResult:
    settings = get_settings()
    if not settings.urlhaus_api_key:
        return ProviderResult(provider="URLhaus")
    try:
        response = httpx.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers={"Auth-Key": settings.urlhaus_api_key}, timeout=5)
        response.raise_for_status()
        payload = response.json()
        known = payload.get("query_status") == "ok"
        return ProviderResult(provider="URLhaus", known=known, malicious=known, confidence=0.96 if known else 0, evidence=["URL référencée comme menace"] if known else [], status="available")
    except (httpx.HTTPError, ValueError, TypeError):
        return ProviderResult(provider="URLhaus", status="unavailable")