"""
vector_store.py
---------------
Manages the FAISS vector store for the fraud knowledge base.

Features:
  - Loads TXT, CSV, PDF, JSON, and Markdown documents
  - Splits large documents into overlapping chunks for better retrieval
  - Persists the FAISS index to disk so it survives restarts
  - rebuild_vector_store() rebuilds from scratch (called after new uploads)
  - Thread-safe: load is synchronous (called via asyncio.to_thread in async contexts)
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import List

from langchain_community.document_loaders import CSVLoader, PyPDFLoader, TextLoader
from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

logger = logging.getLogger(__name__)

# ─── Paths ────────────────────────────────────────────────────────────────────

DOCS_PATH = Path("data/fraud_docs")
INDEX_PATH = Path("data/faiss_index")   # persisted FAISS index lives here

# ─── Splitter: chunk large docs for better retrieval ─────────────────────────

_splitter = RecursiveCharacterTextSplitter(
    chunk_size=800,
    chunk_overlap=120,
    separators=["\n\n", "\n", ".", " ", ""],
)

# ─── Loaders ─────────────────────────────────────────────────────────────────

def _load_txt(path: Path) -> List[Document]:
    try:
        raw = TextLoader(str(path), encoding="utf-8").load()
        return _splitter.split_documents(raw)
    except Exception as e:
        logger.warning("TXT load failed %s: %s", path.name, e)
        return []


def _load_csv(path: Path) -> List[Document]:
    try:
        # CSVLoader turns each row into a Document; no chunking needed
        return CSVLoader(str(path), encoding="utf-8").load()
    except Exception as e:
        logger.warning("CSV load failed %s: %s", path.name, e)
        return []


def _load_pdf(path: Path) -> List[Document]:
    try:
        raw = PyPDFLoader(str(path)).load()
        return _splitter.split_documents(raw)
    except Exception as e:
        logger.warning("PDF load failed %s: %s", path.name, e)
        return []


def _load_json(path: Path) -> List[Document]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        items = data if isinstance(data, list) else [data]
        docs = [
            Document(
                page_content=json.dumps(item, ensure_ascii=False),
                metadata={"source": str(path)},
            )
            for item in items
            if item  # skip empty objects
        ]
        return docs
    except Exception as e:
        logger.warning("JSON load failed %s: %s", path.name, e)
        return []


def _load_markdown(path: Path) -> List[Document]:
    try:
        raw = TextLoader(str(path), encoding="utf-8").load()
        return _splitter.split_documents(raw)
    except Exception as e:
        logger.warning("Markdown load failed %s: %s", path.name, e)
        return []


# ─── Document Collector ───────────────────────────────────────────────────────

def _collect_documents(docs_path: Path) -> List[Document]:
    """Walk the docs directory and load every supported file."""
    docs: List[Document] = []

    loader_map = {
        "txt":      (_load_txt,      "*.txt"),
        "csv":      (_load_csv,      "*.csv"),
        "pdf":      (_load_pdf,      "*.pdf"),
        "json":     (_load_json,     "*.json"),
        "markdown": (_load_markdown, "*.md"),
    }

    for subdir, (loader_fn, glob_pattern) in loader_map.items():
        sub_path = docs_path / subdir
        if not sub_path.exists():
            continue

        files = list(sub_path.glob(glob_pattern))
        for file_path in files:
            batch = loader_fn(file_path)
            docs.extend(batch)
            logger.debug("Loaded %d chunks from %s", len(batch), file_path.name)

    logger.info("Collected %d document chunks from %s", len(docs), docs_path)
    return docs


# ─── Public API ───────────────────────────────────────────────────────────────

def load_vector_store() -> FAISS:
    """
    Return a FAISS vector store.

    Strategy:
      1. If a persisted index exists at INDEX_PATH, load it (fast).
      2. Otherwise build from documents and persist for next time.

    Always call rebuild_vector_store() after uploading new documents
    to regenerate the index.
    """
    embeddings = OpenAIEmbeddings()

    if INDEX_PATH.exists() and any(INDEX_PATH.iterdir()):
        try:
            store = FAISS.load_local(
                str(INDEX_PATH),
                embeddings,
                allow_dangerous_deserialization=True,
            )
            logger.info("FAISS index loaded from disk (%s)", INDEX_PATH)
            return store
        except Exception as e:
            logger.warning("Failed to load persisted index, rebuilding: %s", e)

    return rebuild_vector_store()


def rebuild_vector_store(docs_path: str | Path | None = None) -> FAISS:
    """
    Build the FAISS index from scratch from all documents in docs_path,
    persist it to INDEX_PATH, and return it.

    Called:
      - On first startup (no index on disk)
      - After new documents are uploaded via /knowledge/upload
      - After /knowledge/rebuild is triggered
    """
    path = Path(docs_path) if docs_path else DOCS_PATH
    embeddings = OpenAIEmbeddings()

    docs = _collect_documents(path)

    if not docs:
        # Return an empty (but valid) store so the app doesn't crash
        # when no documents have been uploaded yet
        logger.warning(
            "No documents found in %s — creating empty vector store. "
            "Upload knowledge base documents to enable RAG.",
            path,
        )
        placeholder = Document(
            page_content="Fraud detection knowledge base — no documents loaded yet.",
            metadata={"source": "placeholder"},
        )
        docs = [placeholder]

    store = FAISS.from_documents(docs, embeddings)

    # Persist to disk
    INDEX_PATH.mkdir(parents=True, exist_ok=True)
    store.save_local(str(INDEX_PATH))
    logger.info("FAISS index built with %d chunks and saved to %s", len(docs), INDEX_PATH)

    return store


def add_documents_to_store(new_docs: List[Document]) -> FAISS:
    """
    Incrementally add new documents to the existing index without a full rebuild.
    Useful for the /knowledge/enrich_online endpoint where only a few docs are added.
    """
    embeddings = OpenAIEmbeddings()

    # Load existing or create fresh
    if INDEX_PATH.exists() and any(INDEX_PATH.iterdir()):
        try:
            store = FAISS.load_local(
                str(INDEX_PATH),
                embeddings,
                allow_dangerous_deserialization=True,
            )
        except Exception:
            store = FAISS.from_documents(new_docs, embeddings)
            store.save_local(str(INDEX_PATH))
            return store
    else:
        store = FAISS.from_documents(new_docs, embeddings)
        store.save_local(str(INDEX_PATH))
        return store

    # Split new docs before adding
    chunked = _splitter.split_documents(new_docs)
    store.add_documents(chunked)
    store.save_local(str(INDEX_PATH))
    logger.info("Added %d new chunks to FAISS index", len(chunked))
    return store