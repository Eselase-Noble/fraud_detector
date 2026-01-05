from fastapi import APIRouter

router = APIRouter()

@router.get("/health")
async def health_check():
    return {"status": "ok"}

@router.post("/reload_csv")
async def reload_csv():
    from app.database import load_csv_transactions
    await load_csv_transactions()
    return {"status": "CSV reloaded"}
