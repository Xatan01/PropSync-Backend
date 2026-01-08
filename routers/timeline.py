from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any, List
from supabase_client import admin_client
from utils.auth import get_current_user

router = APIRouter(prefix="/timeline", tags=["timeline"])

# --- TIMELINE TEMPLATES (Master Blueprints) ---

@router.get("/templates")
def get_timeline_templates(user: dict = Depends(get_current_user)):
    """Fetch all reusable blueprints from the dedicated templates table."""
    res = admin_client.table("timeline_templates") \
        .select("*") \
        .eq("agent_id", user["sub"]) \
        .order("template_name") \
        .execute()
    return res.data or []

@router.get("/templates/{template_id}")
def get_single_template(template_id: str, user: dict = Depends(get_current_user)):
    """Fetch one specific blueprint for the builder."""
    res = admin_client.table("timeline_templates") \
        .select("*") \
        .eq("id", template_id) \
        .eq("agent_id", user["sub"]) \
        .single() \
        .execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="Template not found")
    return res.data

@router.post("/save-template")
def save_timeline_template(data: Dict[str, Any], user: dict = Depends(get_current_user)):
    """Handles creating new blueprints or updating/renaming existing ones."""
    payload = {
        "agent_id": user["sub"],
        "template_name": data.get("template_name"),
        "category": data.get("category"),
        "nodes": data.get("nodes"),
        "edges": data.get("edges")
    }
    
    # If editing existing, include the ID to trigger an update (upsert)
    if data.get("id"):
        payload["id"] = data.get("id")

    res = admin_client.table("timeline_templates").upsert(payload).execute()
    return {"status": "success", "message": "Blueprint synced", "data": res.data}

@router.delete("/templates/{id}")
def delete_timeline_template(id: str, user: dict = Depends(get_current_user)):
    """Removes a blueprint from the library."""
    admin_client.table("timeline_templates") \
        .delete() \
        .eq("id", id) \
        .eq("agent_id", user["sub"]) \
        .execute()
    return {"status": "success", "message": "Template deleted"}


# --- CLIENT TIMELINES (Active Transaction Data) ---

@router.get("/client/{client_id}")
def get_client_timeline(client_id: str, user: dict = Depends(get_current_user)):
    """Fetch the active roadmap for a specific client."""
    res = admin_client.table("client_timelines") \
        .select("*") \
        .eq("client_id", client_id) \
        .eq("agent_id", user["sub"]) \
        .execute()
    
    if res.data and len(res.data) > 0:
        return res.data[0]
    
    # Return empty structure so the frontend builder doesn't crash
    return {"nodes": [], "edges": [], "client_id": client_id}

@router.post("/save-client/{client_id}")
def save_client_timeline(client_id: str, data: Dict[str, Any], user: dict = Depends(get_current_user)):
    """Saves the live transaction roadmap for a specific client."""
    # 1. Security check: Owner verification
    client_check = admin_client.table("clients").select("agent_id").eq("id", client_id).single().execute()
    if not client_check.data or client_check.data["agent_id"] != user["sub"]:
        raise HTTPException(status_code=403, detail="Unauthorized client access")

    # 2. Upsert the roadmap (Safe now due to UNIQUE client_id)
    admin_client.table("client_timelines").upsert({
        "client_id": client_id,
        "agent_id": user["sub"],
        "nodes": data.get("nodes"),
        "edges": data.get("edges"),
        "updated_at": "now()"
    }, on_conflict="client_id").execute()
    
    # 3. Log Activity
    admin_client.table("activities").insert({
        "agent_id": user["sub"],
        "client_id": client_id,
        "action": "Roadmap Updated",
        "description": "Updated the property journey roadmap."
    }).execute()
    
    return {"status": "success", "message": "Client timeline updated"}

@router.post("/apply-template/{client_id}/{template_id}")
def apply_template_to_client(client_id: str, template_id: str, user: dict = Depends(get_current_user)):
    """Copies a blueprint into a client's active timeline."""
    # 1. Fetch blueprint
    template = admin_client.table("timeline_templates").select("*").eq("id", template_id).single().execute()
    if not template.data:
        raise HTTPException(status_code=404, detail="Blueprint not found")

    # 2. Push into client timeline
    admin_client.table("client_timelines").upsert({
        "client_id": client_id,
        "agent_id": user["sub"],
        "nodes": template.data["nodes"],
        "edges": template.data["edges"]
    }, on_conflict="client_id").execute()
    
    return {"status": "success", "message": "Blueprint applied to client"}