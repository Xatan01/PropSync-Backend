# routers/timeline.py
from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any
from supabase_client import admin_client
from utils.auth import get_current_user

router = APIRouter(prefix="/timeline", tags=["timeline"])

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
