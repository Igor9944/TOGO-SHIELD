from dataclasses import dataclass
from urllib.parse import urlparse
import re


# Accepte les URLs absolues, y compris lorsqu'elles sont écrites en Markdown.
URL_PATTERN = re.compile(r"https?://[^\s<>]+", re.IGNORECASE)
MARKDOWN_URL_PATTERN = re.compile(r"\[\s*(https?://[^\]\s<>]+)\s*\]\(\s*(https?://[^\s)<>]+)\s*\)", re.IGNORECASE)
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd"}
SUSPICIOUS_TERMS = {"verify", "verification", "secure", "login", "update", "wallet", "claim"}

TRAILING_URL_CHARS = ".,!?;:)]}>'\""


def normalize_url(url: str) -> str:
    """Normalise une URL extraite sans modifier sa destination."""
    value = url.strip()
    value = value.rstrip(TRAILING_URL_CHARS)
    return value


def extract_urls(content: str) -> list[str]:
    """Extrait des URLs HTTP(S), y compris les liens Markdown, sans doublons."""
    if not content:
        return []

    candidates: list[str] = []

    # Dans [https://example.com/login](https://example.com/login), garder l'URL cible.
    for match in MARKDOWN_URL_PATTERN.finditer(content):
        candidates.append(match.group(2))

    # Puis récupérer les URLs ordinaires. Les deux occurrences d'un lien Markdown
    # seront dédupliquées après normalisation.
    candidates.extend(URL_PATTERN.findall(content))

    urls: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        url = normalize_url(candidate)
        if not url:
            continue
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


@dataclass(frozen=True)
class UrlFinding:
    url: str
    indicators: tuple[tuple[str, str, int], ...]


def analyze_urls(content: str) -> tuple[list[str], list[UrlFinding]]:
    urls = extract_urls(content)
    findings: list[UrlFinding] = []
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]
        indicators: list[tuple[str, str, int]] = []
        if parsed.scheme != "https":
            indicators.append(("url", "Lien HTTP non sécurisé", 15))
        if domain in SHORTENERS:
            indicators.append(("url", "Raccourcisseur d'URL", 15))
        if any(term in parsed.path.lower() or term in domain for term in SUSPICIOUS_TERMS):
            indicators.append(("url", "Domaine ou chemin imitant un service de connexion", 20))
        if domain.count("-") >= 2 or len(domain.split(".")) > 3:
            indicators.append(("url", "Domaine inhabituel", 15))
        findings.append(UrlFinding(url, tuple(indicators)))
    return urls, findings
