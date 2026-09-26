import logging

import httpx

from app.core.config import get_settings

from app.schemas.file_analysis import FileAnalysisResponse
from app.schemas.scan import ScanResult
from app.telegram.formatter import format_file_analysis, format_scan_result

logger = logging.getLogger(__name__)
TELEGRAM_MAX_MESSAGE_LENGTH = 4096
TELEGRAM_DOWNLOAD_CHUNK_SIZE = 256 * 1024


async def download_telegram_file(file_id: str) -> tuple[bytes, str]:
    """Download a Telegram file without exposing the bot token in logs."""
    settings = get_settings()
    if not settings.telegram_enabled or not settings.telegram_bot_token:
        raise RuntimeError("Telegram integration is not configured")

    api_url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/getFile"
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(api_url, json={"file_id": file_id})
        response.raise_for_status()
        payload = response.json()

        file_info = payload.get("result") or {}
        file_path = file_info.get("file_path")
        if not file_path:
            raise RuntimeError("Telegram n'a pas retourné le chemin du fichier")

        download_url = f"https://api.telegram.org/file/bot{settings.telegram_bot_token}/{file_path}"
        max_bytes = settings.max_upload_size_mb * 1024 * 1024
        chunks: list[bytes] = []
        total = 0

        async with client.stream("GET", download_url) as download:
            download.raise_for_status()
            async for chunk in download.aiter_bytes(TELEGRAM_DOWNLOAD_CHUNK_SIZE):
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(
                        f"Fichier Telegram trop volumineux (max {settings.max_upload_size_mb} Mo)"
                    )
                chunks.append(chunk)

    return b"".join(chunks), file_path



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


async def send_file_message(chat_id: int, result: FileAnalysisResponse) -> bool:
    return await send_text(chat_id, format_file_analysis(result))


async def ensure_webhook() -> bool:
    """Register the production webhook on Telegram using the canonical API URL."""
    settings = get_settings()
    if not settings.telegram_enabled or not settings.telegram_bot_token:
        return False

    url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/setWebhook"
    payload = {
        "url": "https://togo-shield.vercel.app/api/telegram/webhook",
    }
    if settings.telegram_webhook_secret:
        payload["secret_token"] = settings.telegram_webhook_secret

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return bool(data.get("ok"))
        except httpx.HTTPError as exc:
            logger.warning("Telegram setWebhook failed: %s", exc)
            return False
