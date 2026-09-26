from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.scan import ScanRecord
from app.schemas.scan import ScanRequest, TelegramStatus
from app.services.scan_service import analyze_and_persist
from app.services.file_analyzer import analyze_file, persist_file_analysis
from app.telegram.service import download_telegram_file, send_file_message, send_message, send_text

router = APIRouter(prefix="/api/telegram", tags=["telegram"])


@router.get("/status", response_model=TelegramStatus)
def telegram_status() -> TelegramStatus:
    settings = get_settings()
    configured = bool(settings.telegram_bot_token)
    return TelegramStatus(
        status="connected" if settings.telegram_enabled and configured else "not_configured",
        configured=configured,
        webhook_url="https://togo-shield.vercel.app/api/telegram/webhook",
    )


@router.post("/webhook")
async def telegram_webhook(
    request: Request,
    x_telegram_bot_api_secret_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    settings = get_settings()
    if not settings.telegram_enabled:
        raise HTTPException(status_code=503, detail="Telegram integration is disabled")
    if not settings.telegram_webhook_secret or x_telegram_bot_api_secret_token != settings.telegram_webhook_secret:
        raise HTTPException(status_code=401, detail="Invalid Telegram webhook secret")

    update = await request.json()
    message = update.get("message", {})
    chat = message.get("chat", {})
    chat_id = chat.get("id")
    if not chat_id:
        return {"status": "ignored"}

    message_id = message.get("message_id")
    if message_id and db.scalar(select(ScanRecord.id).where(ScanRecord.telegram_message_id == message_id)):
        return {"status": "duplicate"}

    document = message.get("document")
    photo = message.get("photo") or []

    # Telegram media: document ou photo → téléchargement → validation/extraction/OCR → analyse.
    if document or photo:
        try:
            if document:
                file_id = document.get("file_id")
                filename = document.get("file_name") or "telegram_file"
                content_type = document.get("mime_type") or "application/octet-stream"
            else:
                largest_photo = max(
                    photo,
                    key=lambda item: (item.get("file_size") or 0, item.get("width") or 0, item.get("height") or 0),
                )
                file_id = largest_photo.get("file_id")
                filename = "telegram_photo.jpg"
                content_type = "image/jpeg"

            if not file_id:
                await send_text(int(chat_id), "⚠️ Fichier Telegram invalide ou introuvable.")
                return {"status": "invalid_media"}

            data, _ = await download_telegram_file(str(file_id))
            file_result = analyze_file(
                filename=filename,
                content_type=content_type,
                data=data,
            )
            persist_file_analysis(
                file_result,
                db,
                source="telegram",
                telegram={
                    "chat_id": int(chat_id),
                    "user_id": int(message.get("from", {}).get("id", 0)),
                    "message_id": int(message_id) if message_id else 0,
                },
            )
            sent = await send_file_message(int(chat_id), file_result)
            return {"status": "processed_file" if sent else "processed_file_no_reply"}

        except HTTPException as exc:
            await send_text(int(chat_id), f"⚠️ Fichier non analysé : {exc.detail}")
            return {"status": "unsupported_media"}
        except ValueError as exc:
            await send_text(int(chat_id), f"⚠️ Fichier non analysé : {exc}")
            return {"status": "invalid_media"}
        except Exception as exc:
            import logging
            logging.getLogger(__name__).exception("Telegram media analysis failed: %s", exc)
            await send_text(int(chat_id), "⚠️ Impossible d'analyser ce fichier pour le moment.")
            return {"status": "media_error"}

    text = (message.get("text") or message.get("caption") or "").strip()
    if not text:
        return {"status": "ignored"}

    command = text.split(maxsplit=1)[0].casefold()
    if command in {"/start", "/help"}:
        await send_text(
            int(chat_id),
            "🛡️ TOGO-SHIELD\n\n"
            "Envoyez-moi un message, un lien ou un texte suspect et je l'analyserai.\n\n"
            "Commandes :\n"
            "/start ou /help — aide\n"
            "/status — état du service",
        )
        return {"status": "command"}

    if command == "/status":
        configured = bool(settings.telegram_bot_token)
        status = "actif" if settings.telegram_enabled and configured else "non configuré"
        await send_text(int(chat_id), f"🛡️ TOGO-SHIELD\n\nService Telegram : {status}")
        return {"status": "command"}

    request_data = ScanRequest(content=text, source="telegram")
    result = analyze_and_persist(
        request_data,
        db,
        telegram={
            "chat_id": int(chat_id),
            "user_id": int(message.get("from", {}).get("id", 0)),
            "message_id": int(message_id) if message_id else 0,
        },
    )
    sent = await send_message(int(chat_id), result)
    return {"status": "processed" if sent else "processed_no_reply"}
