"""URLhaus service — appel API URLhaus avec gestion d'erreurs et timeout.

Ce module est SÉPARÉ du moteur TOGO-SHIELD.
Il retourne les résultats bruts d'URLhaus sans transformation en score.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

import httpx

from app.core.config import get_settings

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_TIMEOUT = 5  # secondes

Status = Literal["available", "unavailable", "not_found", "not_configured", "error"]


@dataclass
class UrlhausResult:
    """Résultat brut d'URLhaus — aucune transformation en score."""

    url: str
    found: bool
    url_status: str | None = None  # "online", "offline", "removed", etc.
    threat: str | None = None  # "malware", "phishing", "dropper", etc.
    threat_type: str | None = None  # type de menace plus spécifique
    date_added: str | None = None  # date d'ajout dans URLhaus
    danger_level: int | None = None  # niveau de danger 0-3
    tags: list[str] | None = None
    source: str = "urlhaus"
    status: Status = "available"
    error: str | None = None

    def __post_init__(self):
        if self.tags is None:
            object.__setattr__(self, "tags", [])


def _parse_datetime(value: str | None) -> str | None:
    """Convertit une date ISO d'URLhaus en ISO 8601 compatible."""
    if not value:
        return None
    # URLhaus retourne parfois des formats variés
    try:
        # Essayer de parser et reformater
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.isoformat()
    except (ValueError, AttributeError):
        return value


def query_urlhaus(url: str) -> UrlhausResult:
    """
    Interroge URLhaus pour une URL donnée.

    Retourne un UrlhausResult avec le verdict brut d'URLhaus.
    Ne JAMAIS transformer ce résultat en score ici.
    """
    settings = get_settings()

    # Cas 1: clé non configurée
    if not settings.urlhaus_api_key:
        return UrlhausResult(
            url=url,
            found=False,
            status="not_configured",
            error="URLhaus API key not configured",
        )

    # Cas 2: appel API
    try:
        response = httpx.post(
            URLHAUS_API_URL,
            data={"url": url},
            headers={"Auth-Key": settings.urlhaus_api_key},
            timeout=URLHAUS_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()

        query_status = payload.get("query_status", "")

        if query_status == "ok":
            # URL trouvée dans URLhaus
            result_data = payload.get("result", {})
            return UrlhausResult(
                url=url,
                found=True,
                url_status=result_data.get("url_status", "unknown"),
                threat=result_data.get("threat", "unknown"),
                threat_type=result_data.get("threat_type", None),
                date_added=_parse_datetime(result_data.get("date_added")),
                danger_level=result_data.get("danger_level", None),
                tags=result_data.get("tags", []) or [],
                status="available",
            )
        elif query_status == "no_results":
            return UrlhausResult(
                url=url,
                found=False,
                status="available",
            )
        else:
            return UrlhausResult(
                url=url,
                found=False,
                status="available",
                error=f"URLhaus query_status: {query_status}",
            )

    except httpx.TimeoutException:
        return UrlhausResult(
            url=url,
            found=False,
            status="unavailable",
            error="URLhaus request timed out",
        )
    except httpx.HTTPStatusError as exc:
        return UrlhausResult(
            url=url,
            found=False,
            status="error",
            error=f"URLhaus HTTP error: {exc.response.status_code}",
        )
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        return UrlhausResult(
            url=url,
            found=False,
            status="unavailable",
            error=f"URLhaus request failed: {type(exc).__name__}",
        )
