from app.schemas.scan import Indicator, RiskLevel, ScanResult
from app.telegram.formatter import format_scan_result


def make_result(count: int = 0) -> ScanResult:
    return ScanResult(
        score=70,
        level=RiskLevel.CRITICAL,
        threat_type="phishing",
        indicators=[
            Indicator(type="test", description="x" * 500, weight=1)
            for _ in range(count)
        ],
        recommendations=["Ne cliquez pas sur les liens suspects."],
        source="telegram",
    )


def test_telegram_formatter_contains_core_fields():
    text = format_scan_result(make_result())
    assert "TOGO-SHIELD" in text
    assert "CRITIQUE" in text
    assert "70/100" in text


def test_telegram_message_stays_under_api_limit():
    from app.telegram.service import TELEGRAM_MAX_MESSAGE_LENGTH

    text = format_scan_result(make_result(20))
    assert len(text) > TELEGRAM_MAX_MESSAGE_LENGTH
    assert len(text[:TELEGRAM_MAX_MESSAGE_LENGTH]) == TELEGRAM_MAX_MESSAGE_LENGTH
