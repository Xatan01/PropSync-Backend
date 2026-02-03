# routers/documents.py
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from uuid import UUID

from supabase_client import admin_client
import os
from utils.auth import get_current_user

router = APIRouter(prefix="/documents", tags=["documents"])

BUCKET_NAME = "client-docs"
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DocumentRequestPayload(BaseModel):
    title: str
    description: Optional[str] = None
    required: bool = True
    due_date: Optional[str] = None


class DocumentRequestUpdatePayload(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    required: Optional[bool] = None
    due_date: Optional[str] = None
    status: Optional[str] = None


class UploadUrlPayload(BaseModel):
    file_name: str
    mime_type: Optional[str] = None
    file_size: Optional[int] = None
    request_id: Optional[UUID] = None


class ConfirmUploadPayload(BaseModel):
    storage_path: str
    file_name: str
    mime_type: Optional[str] = None
    file_size: Optional[int] = None
    request_id: Optional[UUID] = None


class ReviewPayload(BaseModel):
    status: str  # approved | rejected
    notes: Optional[str] = None


def ensure_client_owned(client_id: str, user: dict) -> Dict[str, Any]:
    res = (
        admin_client.table("clients")
        .select("id,name")
        .eq("id", client_id)
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Client not found")
    return res.data


@router.get("/clients/{client_id}/requests")
def list_document_requests(client_id: str, user: dict = Depends(get_current_user)):
    ensure_client_owned(client_id, user)
    res = (
        admin_client.table("document_requests")
        .select("*")
        .eq("client_id", client_id)
        .eq("agent_id", user["sub"])
        .order("created_at", desc=True)
        .execute()
    )
    return res.data or []


@router.post("/clients/{client_id}/requests")
def create_document_request(
    client_id: str, payload: DocumentRequestPayload, user: dict = Depends(get_current_user)
):
    client = ensure_client_owned(client_id, user)
    res = (
        admin_client.table("document_requests")
        .insert(
            {
                "agent_id": user["sub"],
                "client_id": client_id,
                "title": payload.title,
                "description": payload.description,
                "required": payload.required,
                "due_date": payload.due_date,
                "status": "requested",
                "created_at": utc_now_iso(),
            }
        )
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to create request")

    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": client_id,
            "action": "requested document",
            "description": f"Requested {payload.title} from {client.get('name') or 'client'}",
        }
    ).execute()

    return res.data[0]


@router.patch("/requests/{request_id}")
def update_document_request(
    request_id: str, payload: DocumentRequestUpdatePayload, user: dict = Depends(get_current_user)
):
    updates = payload.dict(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    res = (
        admin_client.table("document_requests")
        .update(updates)
        .eq("id", request_id)
        .eq("agent_id", user["sub"])
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Request not found")

    req = res.data[0]
    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": req.get("client_id"),
            "action": "updated document request",
            "description": f"Updated request {req.get('title') or ''}".strip(),
        }
    ).execute()

    return req


@router.delete("/requests/{request_id}")
def delete_document_request(request_id: str, user: dict = Depends(get_current_user)):
    req = (
        admin_client.table("document_requests")
        .select("id, client_id, title")
        .eq("id", request_id)
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    if not req.data:
        raise HTTPException(status_code=404, detail="Request not found")

    docs_res = (
        admin_client.table("client_documents")
        .select("id, storage_path")
        .eq("request_id", request_id)
        .eq("agent_id", user["sub"])
        .execute()
    )
    docs = docs_res.data or []
    storage_paths = [doc.get("storage_path") for doc in docs if doc.get("storage_path")]
    if storage_paths:
        try:
            admin_client.storage.from_(BUCKET_NAME).remove(storage_paths)
        except Exception:
            pass

    if docs:
        admin_client.table("client_documents").delete().eq("request_id", request_id).eq(
            "agent_id", user["sub"]
        ).execute()

    res = (
        admin_client.table("document_requests")
        .delete()
        .eq("id", request_id)
        .eq("agent_id", user["sub"])
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to delete request")

    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": req.data.get("client_id"),
            "action": "deleted document request",
            "description": f"Deleted request {req.data.get('title') or ''}".strip(),
        }
    ).execute()

    return {"status": "deleted", "documents_removed": len(docs)}


@router.get("/clients/{client_id}/documents")
def list_client_documents(client_id: str, user: dict = Depends(get_current_user)):
    ensure_client_owned(client_id, user)
    res = (
        admin_client.table("client_documents")
        .select("*")
        .eq("client_id", client_id)
        .eq("agent_id", user["sub"])
        .order("created_at", desc=True)
        .execute()
    )
    return res.data or []


@router.post("/clients/{client_id}/upload-url")
def create_upload_url(
    client_id: str, payload: UploadUrlPayload, user: dict = Depends(get_current_user)
):
    ensure_client_owned(client_id, user)
    if not payload.file_name:
        raise HTTPException(status_code=400, detail="file_name is required")

    safe_name = payload.file_name.replace("/", "_")
    storage_path = f"{user['sub']}/{client_id}/{datetime.now(timezone.utc).timestamp()}_{safe_name}"

    signed = admin_client.storage.from_(BUCKET_NAME).create_signed_upload_url(storage_path)
    if not signed:
        raise HTTPException(status_code=500, detail="Failed to create upload URL")

    signed_url = signed.get("signed_url")
    if signed_url and not signed_url.startswith("http"):
        signed_url = signed_url.lstrip("/")
        signed_url = f"{SUPABASE_URL}/storage/v1/{signed_url}"

    return {"storage_path": storage_path, "signed_url": signed_url}


@router.post("/clients/{client_id}/documents/confirm")
def confirm_upload(
    client_id: str, payload: ConfirmUploadPayload, user: dict = Depends(get_current_user)
):
    client = ensure_client_owned(client_id, user)
    res = (
        admin_client.table("client_documents")
        .insert(
            {
                "agent_id": user["sub"],
                "client_id": client_id,
                "uploader_user_id": user["sub"],
                "uploader_role": "agent",
                "file_name": payload.file_name,
                "storage_path": payload.storage_path,
                "mime_type": payload.mime_type,
                "file_size": payload.file_size,
                "request_id": str(payload.request_id) if payload.request_id else None,
                "status": "shared",
                "created_at": utc_now_iso(),
            }
        )
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to save document")

    if payload.request_id:
        admin_client.table("document_requests").update(
            {"status": "submitted"}
        ).eq("id", str(payload.request_id)).execute()

    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": client_id,
            "action": "uploaded document",
            "description": f"Uploaded {payload.file_name} for {client.get('name') or 'client'}",
        }
    ).execute()

    return res.data[0]


@router.delete("/{document_id}")
def delete_document(document_id: str, user: dict = Depends(get_current_user)):
    doc = (
        admin_client.table("client_documents")
        .select("id, client_id, storage_path, file_name")
        .eq("id", document_id)
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    if not doc.data:
        raise HTTPException(status_code=404, detail="Document not found")

    storage_path = doc.data.get("storage_path")
    if storage_path:
        try:
            admin_client.storage.from_(BUCKET_NAME).remove([storage_path])
        except Exception:
            pass

    res = (
        admin_client.table("client_documents")
        .delete()
        .eq("id", document_id)
        .eq("agent_id", user["sub"])
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to delete document")

    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": doc.data.get("client_id"),
            "action": "deleted document",
            "description": f"Deleted document {doc.data.get('file_name') or ''}".strip(),
        }
    ).execute()

    return {"status": "deleted"}


@router.patch("/{document_id}/review")
def review_document(
    document_id: str, payload: ReviewPayload, user: dict = Depends(get_current_user)
):
    if payload.status not in {"approved", "rejected"}:
        raise HTTPException(status_code=400, detail="Invalid status")

    existing = (
        admin_client.table("client_documents")
        .select("id,client_id,uploader_role,file_name,request_id")
        .eq("id", document_id)
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    if not existing.data:
        raise HTTPException(status_code=404, detail="Document not found")
    if existing.data.get("uploader_role") != "client":
        raise HTTPException(status_code=400, detail="Only client uploads can be reviewed")

    res = (
        admin_client.table("client_documents")
        .update(
            {
                "status": payload.status,
                "notes": payload.notes,
                "approved_by": user["sub"],
                "approved_at": utc_now_iso(),
            }
        )
        .eq("id", document_id)
        .eq("agent_id", user["sub"])
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Document not found")

    doc = res.data[0]
    request_id = doc.get("request_id")
    if request_id:
        admin_client.table("document_requests").update(
            {"status": payload.status}
        ).eq("id", request_id).execute()

    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": doc.get("client_id"),
            "action": f"{payload.status} document",
            "description": f"{payload.status.title()} document {doc.get('file_name') or ''}".strip(),
        }
    ).execute()

    return doc

@router.get("/{document_id}/download")
def download_document(document_id: str, user: dict = Depends(get_current_user)):
    doc = (
        admin_client.table("client_documents")
        .select("id, client_id, storage_path, file_name")
        .eq("id", document_id)
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    if not doc.data:
        raise HTTPException(status_code=404, detail="Document not found")

    storage_path = doc.data.get("storage_path")
    if not storage_path:
        raise HTTPException(status_code=400, detail="Document has no storage path")

    signed = admin_client.storage.from_(BUCKET_NAME).create_signed_url(storage_path, 60 * 60)
    signed_url = None
    if isinstance(signed, dict):
        signed_url = signed.get("signed_url") or signed.get("signedURL")
    if signed_url and not signed_url.startswith("http"):
        if not SUPABASE_URL:
            raise HTTPException(status_code=500, detail="SUPABASE_URL not configured")
        signed_url = f"{SUPABASE_URL}/storage/v1/{signed_url}"

    if not signed_url:
        raise HTTPException(status_code=500, detail="Failed to create signed download URL")

    return {"signed_url": signed_url, "file_name": doc.data.get("file_name")}
