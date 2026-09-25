from typing import Protocol

from app.schemas.scan import ProviderResult


class ThreatProvider(Protocol):
    name: str

    def inspect(self, url: str) -> ProviderResult:
        ...