from fastapi import APIRouter, Header, HTTPException
from typing import Optional, Dict, Any
from datetime import datetime
from supabase_client import admin_client, auth_client

router = APIRouter(prefix="/clients", tags=["clients"])

@router.get("/")
def list_clients(Authorization: Optional[str] = Header(None)):
    if not Authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = Authorization.replace("Bearer ", "")
    user = auth_client.auth.get_user(token)
    agent_id = user.user.id

    res = (
        admin_client.table("clients")
        .select("*")
        .eq("agent_id", agent_id)
        .order("created_at", desc=True)
        .execute()
    )
    return res.data or []


@router.post("/")
def create_client(data: Dict[str, Any], Authorization: Optional[str] = Header(None)):
    if not Authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = Authorization.replace("Bearer ", "")
    user = auth_client.auth.get_user(token)
    agent_id = user.user.id

    new_client = {
        "agent_id": agent_id,
        "name": data.get("name"),
        "email": data.get("email"),
        "phone": data.get("phone"),
        "property": data.get("property"),
        "transactionType": data.get("transactionType"),
        "status": "pending",
        "progress": 0,
        "value": 0,
        "invite_status": "uninvited",
        "invited": False,
    }

    res = admin_client.table("clients").insert(new_client).execute()
    client = res.data[0]

    admin_client.table("activities").insert({
        "agent_id": agent_id,
        "client_id": client["id"],
        "action": "created client",
        "description": f"Added new client {client['name']}"
    }).execute()

    return client


@router.post("/invite/{client_id}")
def invite_client(client_id: str, Authorization: Optional[str] = Header(None)):
    token = Authorization.replace("Bearer ", "")
    user = auth_client.auth.get_user(token)
    agent_id = user.user.id

    res = (
        admin_client.table("clients")
        .select("*")
        .eq("id", client_id)
        .eq("agent_id", agent_id)
        .single()
        .execute()
    )

    client = res.data

    created = admin_client.auth.admin.create_user({
        "email": client["email"],
        "user_metadata": {"role": "client", "name": client["name"]},
        "email_confirm": False,
    })

    admin_client.table("clients").update({
        "auth_user_id": created.user.id,
        "invited": True,
        "invite_status": "pending",
        "invited_at": datetime.utcnow().isoformat()
    }).eq("id", client_id).execute()

    admin_client.table("activities").insert({
        "agent_id": agent_id,
        "client_id": client_id,
        "action": "sent invite",
        "description": f"Sent invite to {client['name']} ({client['email']})"
    }).execute()

    return {"status": "invited"}
