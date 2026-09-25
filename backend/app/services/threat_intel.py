from app.threat_intelligence import inspect_url


def lookup_url(url: str) -> list[tuple[str, str, int]]:
    indicators: list[tuple[str, str, int]] = []
    for result in inspect_url(url):
        if result.malicious:
            indicators.append(("reputation", f"{result.provider} signale cette URL comme menace", 35))
    return indicators