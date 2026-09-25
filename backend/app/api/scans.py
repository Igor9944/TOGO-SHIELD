from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.models.scan import ScanRecord
from app.schemas.scan import ScanRecordResponse, ScanRequest, ScanResult
from app.services.scan_service import analyze_and_persist, list_records, to_response

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanResult)
def create_scan(request: ScanRequest, db: Session = Depends(get_db)) -> ScanResult:
    return analyze_and_persist(request, db)


@router.get("", response_model=list[ScanRecordResponse])
def get_scans(limit: int = 50, db: Session = Depends(get_db)) -> list[ScanRecordResponse]:
    return list_records(db, min(max(limit, 1), 100))


@router.get("/{scan_id}", response_model=ScanRecordResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> ScanRecordResponse:
    record = db.scalar(select(ScanRecord).where(ScanRecord.id == scan_id))
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return to_response(record)


@router.post("/image", response_model=ScanResult)
async def scan_image(file: UploadFile = File(...), db: Session = Depends(get_db)) -> ScanResult:
    settings = get_settings()
    if file.content_type not in {"image/png", "image/jpeg", "image/webp"}:
        raise HTTPException(status_code=415, detail="Unsupported image type")
    payload = await file.read(settings.max_upload_size_mb * 1024 * 1024 + 1)
    if len(payload) > settings.max_upload_size_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Image is too large")
    try:
        from io import BytesIO
        from PIL import Image
        import pytesseract

        text = pytesseract.image_to_string(Image.open(BytesIO(payload))).strip()
    except (ImportError, OSError):
        raise HTTPException(status_code=503, detail="OCR is not available") from None
    if not text:
        raise HTTPException(status_code=422, detail="No readable text found")
    return analyze_and_persist(ScanRequest(content=text, source="web"), db, media_type=file.content_type)