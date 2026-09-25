import httpx

from app.core.config import get_settings
from app.schemas.scan import ScanResult
from app.telegram.formatter import format_scan_result


async def send_message(chat_id: int, result: ScanResult) -> None:
    settings = get_settings()
    if not settings.telegram_enabled or not settings.telegram_bot_token:
        return
    url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(url, json={"chat_id": chat_id, "text": format_scan_result(result)})
        response.raise_for_status()