# routers/clients.py
from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any
from datetime import datetime
from supabase_client import admin_client
from utils.auth import get_current_user

router = APIRouter(prefix="/clients", tags=["clients"])

@router.get("/")
def list_clients(user: dict = Depends(get_current_user)):
    res = (
        admin_client.table("clients")
        .select("*")
        .eq("agent_id", user["sub"])
        .order("created_at", desc=True)
        .execute()
    )
    return res.data or []

@router.post("/")
def create_client(data: Dict[str, Any], user: dict = Depends(get_current_user)):
    new_client = {
        "agent_id": user["sub"],
        "name": data.get("name"),
        "email": data.get("email"),
        "property": data.get("property"),
        "status": "pending",
        "value": 0,
        "invite_status": "uninvited",
    }

    res = admin_client.table("clients").insert(new_client).execute()
    client = res.data[0]

    admin_client.table("activities").insert({
        "agent_id": user["sub"],
        "client_id": client["id"],
        "action": "created client",
        "description": f"Added new client {client['name']}"
    }).execute()

    return client
