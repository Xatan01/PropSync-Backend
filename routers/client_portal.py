from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime, timezone
import os
import re

from supabase_client import admin_client, auth_client

router = APIRouter(prefix="/client", tags=["client"])

BUCKET_NAME = "client-docs"
SUPABASE_URL = (os.getenv("SUPABASE_URL") or "").rstrip("/")


def _get_client_from_token(authorization: str) -> Dict[str, Any]:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    token = authorization.replace("Bearer ", "")

    user = auth_client.auth.get_user(token)
    auth_user = getattr(user, "user", None)
    if not auth_user:
        raise HTTPException(status_code=401, detail="Invalid token")

    role = (auth_user.user_metadata or {}).get("role")
    if role != "client":
        raise HTTPException(status_code=403, detail="Client access only")

    res = (
        admin_client.table("clients")
        .select("*")
        .eq("auth_user_id", auth_user.id)
        .single()
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Client record not found")
    return res.data


class UploadUrlPayload(BaseModel):
    file_name: str
    mime_type: Optional[str] = None
    file_size: Optional[int] = None
    request_id: Optional[str] = None


class ConfirmUploadPayload(BaseModel):
    storage_path: str
    file_name: str
    mime_type: Optional[str] = None
    file_size: Optional[int] = None
    request_id: Optional[str] = None


@router.get("/me")
def my_profile(Authorization: str = Header(...)):
    return _get_client_from_token(Authorization)


@router.get("/requests")
def my_requests(Authorization: str = Header(...)):
    client = _get_client_from_token(Authorization)
    res = (
        admin_client.table("document_requests")
        .select("*")
        .eq("client_id", client["id"])
        .order("created_at", desc=True)
        .execute()
    )
    return res.data or []


@router.get("/documents")
def my_documents(Authorization: str = Header(...)):
    client = _get_client_from_token(Authorization)
    res = (
        admin_client.table("client_documents")
        .select("*")
        .eq("client_id", client["id"])
        .order("created_at", desc=True)
        .execute()
    )
    return res.data or []


@router.get("/timeline")
def my_timeline(Authorization: str = Header(...)):
    client = _get_client_from_token(Authorization)
    res = (
        admin_client.table("client_timelines")
        .select("*")
        .eq("client_id", client["id"])
        .single()
        .execute()
    )
    return res.data or {}


@router.post("/upload-url")
def create_upload_url(payload: UploadUrlPayload, Authorization: str = Header(...)):
    client = _get_client_from_token(Authorization)
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", payload.file_name)
    storage_path = f"{client['id']}/{datetime.now(timezone.utc).timestamp()}_{safe_name}"
    signed = admin_client.storage.from_(BUCKET_NAME).create_signed_upload_url(storage_path)
    signed_url = signed.get("signed_url") if isinstance(signed, dict) else None
    if signed_url and not signed_url.startswith("http"):
        if not SUPABASE_URL:
            raise HTTPException(status_code=500, detail="SUPABASE_URL not configured")
        signed_url = f"{SUPABASE_URL}/storage/v1/{signed_url}"
    if not signed_url:
        raise HTTPException(status_code=500, detail="Failed to create signed upload URL")

    return {"storage_path": storage_path, "signed_url": signed_url}


@router.post("/documents/confirm")
def confirm_upload(payload: ConfirmUploadPayload, Authorization: str = Header(...)):
    client = _get_client_from_token(Authorization)
    insert = (
        admin_client.table("client_documents")
        .insert(
            {
                "agent_id": client["agent_id"],
                "client_id": client["id"],
                "uploader_user_id": client.get("auth_user_id"),
                "uploader_role": "client",
                "file_name": payload.file_name,
                "storage_path": payload.storage_path,
                "mime_type": payload.mime_type,
                "file_size": payload.file_size,
                "status": "submitted",
                "request_id": payload.request_id,
            }
        )
        .execute()
    )

    if payload.request_id:
        admin_client.table("document_requests").update(
            {"status": "submitted"}
        ).eq("id", payload.request_id).execute()

    admin_client.table("activities").insert(
        {
            "agent_id": client["agent_id"],
            "client_id": client["id"],
            "action": "client uploaded document",
            "description": f"Client uploaded {payload.file_name}",
        }
    ).execute()

    return insert.data[0] if insert.data else {"status": "submitted"}
