"""
knowledge.py
------------
Admin endpoints for managing the fraud knowledge base:
  - Upload documents (PDF, CSV, TXT, JSON)
  - Search the vector store
  - Reload / rebuild the vector store
  - Enrich with live web content via Tavily
"""
from __future__ import annotations

import os
import asyncio
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, UploadFile, Query
from pydantic import BaseModel

from app.vector_store import load_vector_store, rebuild_vector_store
from app.database import save_csv_to_db

router = APIRouter(prefix="/knowledge", tags=["Knowledge Base"])

# ─── Constants ────────────────────────────────────────────────────────────────

BASE_DIR = "data/fraud_docs"

ALLOWED_EXTENSIONS = {
    ".csv": "csv",
    ".pdf": "pdf",
    ".txt": "txt",
    ".json": "json",
    ".md": "markdown",
}

MAX_FILE_SIZE_MB = 50

# ─── State ────────────────────────────────────────────────────────────────────

_vector_store = load_vector_store()
_retriever = _vector_store.as_retriever(search_kwargs={"k": 5})


def _refresh_retriever():
    global _vector_store, _retriever
    _vector_store = load_vector_store()
    _retriever = _vector_store.as_retriever(search_kwargs={"k": 5})


# ─── Models ───────────────────────────────────────────────────────────────────

class SearchRequest(BaseModel):
    query: str
    k: int = 5

class SearchResult(BaseModel):
    content: str
    source: Optional[str] = None
    score: Optional[float] = None

class OnlineEnrichRequest(BaseModel):
    topic: str
    max_results: int = 5


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/search", response_model=List[SearchResult], summary="Search the fraud knowledge base")
async def search_docs(request: SearchRequest):
    request.k = min(max(request.k, 1), 20)
    retriever = _vector_store.as_retriever(search_kwargs={"k": request.k})

    try:
        docs = await asyncio.to_thread(retriever.get_relevant_documents, request.query)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {e}")

    return [
        SearchResult(
            content=d.page_content,
            source=d.metadata.get("source"),
            score=d.metadata.get("score"),
        )
        for d in docs
    ]


@router.post("/reload", summary="Reload the vector store from disk")
async def reload_vector_store(background_tasks: BackgroundTasks):
    background_tasks.add_task(_refresh_retriever)
    return {"status": "Vector store reload triggered in background."}


@router.post("/rebuild", summary="Rebuild the vector store from all documents")
async def rebuild(background_tasks: BackgroundTasks):
    async def _rebuild():
        await asyncio.to_thread(rebuild_vector_store, BASE_DIR)
        _refresh_retriever()

    background_tasks.add_task(_rebuild)
    return {"status": "Full vector store rebuild triggered. This may take a few minutes."}


@router.post("/upload", summary="Upload a document to the knowledge base")
async def upload_document(file: UploadFile, background_tasks: BackgroundTasks):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    _, ext = os.path.splitext(file.filename.lower())

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {list(ALLOWED_EXTENSIONS.keys())}",
        )

    content = await file.read()
    await file.close()

    # File size check
    size_mb = len(content) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({size_mb:.1f} MB). Max allowed: {MAX_FILE_SIZE_MB} MB.",
        )

    subdir = ALLOWED_EXTENSIONS[ext]
    target_dir = os.path.join(BASE_DIR, subdir)
    os.makedirs(target_dir, exist_ok=True)
    file_path = os.path.join(target_dir, file.filename)

    try:
        with open(file_path, "wb") as f:
            f.write(content)
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {e}")

    # For CSVs, also index into database
    if ext == ".csv":
        background_tasks.add_task(save_csv_to_db, file.filename, content)

    # Trigger async vector store rebuild in background
    background_tasks.add_task(_refresh_retriever)

    return {
        "status": "success",
        "filename": file.filename,
        "saved_to": file_path,
        "size_mb": round(size_mb, 2),
        "note": "Vector store will be refreshed in the background.",
    }


@router.post("/enrich_online", summary="Fetch live fraud intelligence from the web and add to knowledge base")
async def enrich_from_web(request: OnlineEnrichRequest, background_tasks: BackgroundTasks):
    """
    Uses Tavily to fetch real-time fraud threat intelligence and saves it to
    the knowledge base for future RAG queries.
    """
    tavily_key = os.getenv("TAVILY_API_KEY")
    if not tavily_key:
        raise HTTPException(
            status_code=503,
            detail="TAVILY_API_KEY not configured. Online enrichment unavailable.",
        )

    try:
        from langchain_community.tools.tavily_search import TavilySearchResults
        tool = TavilySearchResults(max_results=request.max_results, tavily_api_key=tavily_key)
        results = await asyncio.to_thread(tool.invoke, request.topic)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Web fetch failed: {e}")

    if not results:
        return {"status": "no_results", "topic": request.topic}

    # Persist fetched content as a .txt doc
    content_lines = []
    for r in results:
        content_lines.append(f"Source: {r.get('url', 'unknown')}")
        content_lines.append(r.get("content", ""))
        content_lines.append("---")

    doc_content = "\n".join(content_lines)
    safe_topic = request.topic[:50].replace(" ", "_").replace("/", "-")
    from datetime import datetime
    filename = f"online_intel_{safe_topic}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    target_dir = os.path.join(BASE_DIR, "txt")
    os.makedirs(target_dir, exist_ok=True)
    file_path = os.path.join(target_dir, filename)

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(doc_content)

    background_tasks.add_task(_refresh_retriever)

    return {
        "status": "success",
        "topic": request.topic,
        "documents_fetched": len(results),
        "saved_to": file_path,
        "note": "Vector store will be refreshed with this new intelligence.",
    }


@router.get("/stats", summary="Get knowledge base statistics")
async def knowledge_stats():
    stats = {"directories": {}}
    total_files = 0

    for subdir in ALLOWED_EXTENSIONS.values():
        dir_path = os.path.join(BASE_DIR, subdir)
        if os.path.exists(dir_path):
            files = os.listdir(dir_path)
            stats["directories"][subdir] = len(files)
            total_files += len(files)
        else:
            stats["directories"][subdir] = 0

    stats["total_documents"] = total_files
    return stats