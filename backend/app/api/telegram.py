from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.scan import ScanRecord
from app.schemas.scan import ScanRequest, TelegramStatus
from app.services.scan_service import analyze_and_persist
from app.telegram.service import send_message

router = APIRouter(prefix="/api/telegram", tags=["telegram"])


@router.get("/status", response_model=TelegramStatus)
def telegram_status() -> TelegramStatus:
    settings = get_settings()
    configured = bool(settings.telegram_bot_token)
    return TelegramStatus(status="connected" if settings.telegram_enabled and configured else "not_configured", configured=configured, webhook_url=settings.telegram_webhook_url)


@router.post("/webhook")
async def telegram_webhook(request: Request, x_telegram_bot_api_secret_token: str | None = Header(default=None), db: Session = Depends(get_db)) -> dict[str, str]:
    settings = get_settings()
    if not settings.telegram_webhook_secret or x_telegram_bot_api_secret_token != settings.telegram_webhook_secret:
        raise HTTPException(status_code=401, detail="Invalid Telegram webhook secret")
    update = await request.json()
    message = update.get("message", {})
    text = message.get("text") or message.get("caption")
    chat = message.get("chat", {})
    if not text or not chat.get("id"):
        return {"status": "ignored"}
    message_id = message.get("message_id")
    if message_id and db.scalar(select(ScanRecord.id).where(ScanRecord.telegram_message_id == message_id)):
        return {"status": "duplicate"}
    request_data = ScanRequest(content=text, source="telegram")
    result = analyze_and_persist(request_data, db, telegram={"chat_id": int(chat["id"]), "user_id": int(message.get("from", {}).get("id", 0)), "message_id": int(message_id) if message_id else 0})
    await send_message(int(chat["id"]), result)
    return {"status": "processed"}