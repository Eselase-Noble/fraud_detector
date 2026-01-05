from fastapi import APIRouter
from typing import List
from app.vector_store import load_vector_store

router = APIRouter()

# Load FAISS retriever globally
vector_store = load_vector_store()
retriever = vector_store.as_retriever(search_kwargs={"k": 5})

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
