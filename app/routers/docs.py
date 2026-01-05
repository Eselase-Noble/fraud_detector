import os

from fastapi import APIRouter, UploadFile, HTTPException
from typing import List

from starlette.formparsers import MultipartPart

from app.database import save_csv_to_db
from app.vector_store import load_vector_store

router = APIRouter()

# Load FAISS retriever globally
vector_store = load_vector_store()
retriever = vector_store.as_retriever(search_kwargs={"k": 5})

BASE_DIR = "data/fraud_docs"

EXTENSION_DIRS = {
    ".csv": "csv",
    ".pdf": "pdf",
    ".txt": "txt",
    ".json": "json",
}

# Search vector store
@router.post("/search_docs")
async def search_docs(query: str) -> List[str]:
    docs = retriever.get_relevant_documents(query)
    return [d.page_content for d in docs]

# Reload vector store
@router.post("/update_vector_store")
async def update_vector_store():
    global vector_store, retriever
    vector_store = load_vector_store()
    retriever = vector_store.as_retriever(search_kwargs={"k": 5})
    return {"status": "Vector store updated"}

@router.post("/admin/upload_docs")
async def updateKnowledgeBase(file: UploadFile):
    # Get file extension safely
    _, ext = os.path.splitext(file.filename.lower())

    if ext not in EXTENSION_DIRS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {ext}"
        )

    # Build target directory
    subdir = EXTENSION_DIRS[ext]
    target_dir = os.path.join(BASE_DIR, subdir)
    os.makedirs(target_dir, exist_ok=True)

    # Save file path
    file_path = os.path.join(target_dir, file.filename)

    # Save file asynchronously
    try:
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
    finally:
        await file.close()

    # Optional: save metadata or content to DB
    # if ext == ".csv":
    #     await save_csv_to_db(file.filename, content)

    return {
        "status": "success",
        "filename": file.filename,
        "saved_to": file_path,
    }