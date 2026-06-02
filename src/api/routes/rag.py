"""RAG ingestion and search endpoints."""
from __future__ import annotations

from fastapi import APIRouter, UploadFile
from pydantic import BaseModel

from src.rag.loader import ingest_raw_text
from src.rag.vectorstore import get_vectorstore

router = APIRouter(prefix="/rag", tags=["rag"])


class RawIngestRequest(BaseModel):
    text: str
    metadata: dict = {}


@router.post("/ingest/text")
async def ingest_text(req: RawIngestRequest) -> dict:
    """Ingest arbitrary firewall config text into the vector store."""
    count = ingest_raw_text(req.text, req.metadata)
    return {"documents_created": count}


@router.post("/ingest/file")
async def ingest_file(file: UploadFile, vendor: str = "", device: str = "") -> dict:
    """Upload a firewall config file and ingest it."""
    content = (await file.read()).decode("utf-8", errors="replace")
    meta = {"filename": file.filename, "vendor": vendor, "device": device}
    count = ingest_raw_text(content, meta)
    return {"filename": file.filename, "documents_created": count}


@router.get("/search")
async def search(q: str, vendor: str = "", device: str = "", limit: int = 10) -> dict:
    """Semantic search over the vector store."""
    vs = get_vectorstore()
    where: dict = {}
    if vendor:
        where["vendor"] = vendor
    if device:
        where["device"] = device
    docs = vs.similarity_search(q, k=limit, filter=where or None)
    return {
        "query": q,
        "results": [
            {"content": d.page_content, "metadata": d.metadata} for d in docs
        ],
    }


@router.get("/status")
async def status() -> dict:
    """Return vector store collection info."""
    vs = get_vectorstore()
    col = vs._collection
    return {"collection": col.name, "document_count": col.count()}
