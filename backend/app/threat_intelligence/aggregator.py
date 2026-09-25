from app.schemas.scan import ProviderResult
from app.threat_intelligence import urlhaus, virustotal


def inspect_url(url: str) -> list[ProviderResult]:
    return [virustotal.inspect(url), urlhaus.inspect(url)]