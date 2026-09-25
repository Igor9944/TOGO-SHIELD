from dataclasses import dataclass
from urllib.parse import urlparse
import re


URL_PATTERN = re.compile(r"https?://[^\s<>]+", re.IGNORECASE)
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd"}
SUSPICIOUS_TERMS = {"verify", "verification", "secure", "login", "update", "wallet", "claim"}


@dataclass(frozen=True)
class UrlFinding:
    url: str
    indicators: tuple[tuple[str, str, int], ...]


def analyze_urls(content: str) -> tuple[list[str], list[UrlFinding]]:
    urls = [url.rstrip(".,!?;:)") for url in URL_PATTERN.findall(content)]
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