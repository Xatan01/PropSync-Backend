# routers/timeline.py
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Any, Optional
from datetime import datetime, timezone

from supabase_client import admin_client
from utils.auth import get_current_user

router = APIRouter(prefix="/timeline", tags=["timeline"])


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SaveTemplateRequest(BaseModel):
    id: Optional[str] = None  # if provided -> update; else insert new
    template_name: str
    category: str = "HDB"
    nodes: Any = []
    edges: Any = []


class SaveClientTimelineRequest(BaseModel):
    nodes: Any = []
    edges: Any = []


@router.get("/templates")
def get_timeline_templates(user: dict = Depends(get_current_user)):
    res = (
        admin_client.table("timeline_templates")
        .select("*")
        .eq("agent_id", user["sub"])
        .order("template_name")
        .execute()
    )
    return res.data or []


@router.get("/templates/{template_id}")
def get_single_template(template_id: str, user: dict = Depends(get_current_user)):
    res = (
        admin_client.table("timeline_templates")
        .select("*")
        .eq("id", template_id)
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Template not found")
    return res.data


@router.post("/save-template")
def save_template(payload: SaveTemplateRequest, user: dict = Depends(get_current_user)):
    data = {
        "agent_id": user["sub"],
        "template_name": payload.template_name,
        "category": (payload.category or "HDB").upper(),
        "nodes": payload.nodes or [],
        "edges": payload.edges or [],
    }

    # Update existing
    if payload.id:
        res = (
            admin_client.table("timeline_templates")
            .update(data)
            .eq("id", payload.id)
            .eq("agent_id", user["sub"])
            .execute()
        )
        if not res.data:
            raise HTTPException(status_code=404, detail="Template not found or not owned by agent")
        return res.data[0]

    # Insert new
    res = admin_client.table("timeline_templates").insert(data).execute()
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to create template")
    return res.data[0]


@router.get("/{client_id}")
def get_client_timeline(client_id: str, user: dict = Depends(get_current_user)):
    res = (
        admin_client.table("client_timelines")
        .select("*")
        .eq("client_id", client_id)
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    # If none exists, return empty (so frontend opens template picker)
    return res.data or {"nodes": [], "edges": []}


@router.post("/save/{client_id}")
def save_client_timeline(client_id: str, payload: SaveClientTimelineRequest, user: dict = Depends(get_current_user)):
    # Upsert client timeline
    res = (
        admin_client.table("client_timelines")
        .upsert(
            {
                "client_id": client_id,
                "agent_id": user["sub"],
                "nodes": payload.nodes or [],
                "edges": payload.edges or [],
                "updated_at": utc_now_iso(),
            },
            on_conflict="client_id",
        )
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to save client timeline")
    return res.data[0]


@router.delete("/templates/{template_id}")
def delete_template(template_id: str, user: dict = Depends(get_current_user)):
    res = (
        admin_client.table("timeline_templates")
        .delete()
        .eq("id", template_id)
        .eq("agent_id", user["sub"])
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Template not found or not owned by agent")
    return {"status": "deleted"}
