import logging

import httpx

from app.core.config import get_settings
from app.schemas.scan import ScanResult
from app.telegram.formatter import format_scan_result

logger = logging.getLogger(__name__)
TELEGRAM_MAX_MESSAGE_LENGTH = 4096


async def send_text(chat_id: int, text: str) -> bool:
    settings = get_settings()
    if not settings.telegram_enabled or not settings.telegram_bot_token:
        return False

    url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text[:TELEGRAM_MAX_MESSAGE_LENGTH]}

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            return True
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "Telegram sendMessage failed: status=%s body=%s",
                exc.response.status_code,
                exc.response.text[:500],
            )
        except httpx.HTTPError as exc:
            logger.warning("Telegram sendMessage request failed: %s", exc)
    return False


async def send_message(chat_id: int, result: ScanResult) -> bool:
    return await send_text(chat_id, format_scan_result(result))
