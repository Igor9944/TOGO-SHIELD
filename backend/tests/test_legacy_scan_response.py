import json
from datetime import datetime, timezone

from app.models.scan import ScanRecord
from app.services.scan_service import to_response


def test_scan_response_accepts_legacy_provider_results_without_provider_name():
    record = ScanRecord(
        id=1,
        source="web",
        content="legacy scan",
        score=0,
        level="low",
        threat_type="low risk",
        confidence=25,
        indicators_json="[]",
        threat_intelligence_json=json.dumps([{"known": False}, {"known": False}]),
        score_breakdown_json="[]",
        created_at=datetime.now(timezone.utc),
    )

    response = to_response(record)

    assert [item.provider for item in response.threat_intelligence] == ["unknown", "unknown"]