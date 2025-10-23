# routers/clients.py
from fastapi import APIRouter, Header, HTTPException
from typing import Optional
from supabase_client import admin_client, auth_client

router = APIRouter(prefix="/clients", tags=["clients"])


@router.get("")
def list_clients(Authorization: Optional[str] = Header(None)):
    """Return all clients belonging to the logged-in agent."""
    if not Authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = Authorization.replace("Bearer ", "")
    try:
        # ✅ Verify the Supabase JWT and get user info
        user = auth_client.auth.get_user(token)
        user_id = user.user.id
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # ✅ Fetch only clients belonging to this agent
    res = (
        admin_client.table("clients")
        .select("*")
        .eq("agent_id", user_id)
        .execute()
    )
    return res.data


@router.post("")
def create_client(data: dict, Authorization: Optional[str] = Header(None)):
    """Insert a new client under the logged-in agent."""
    if not Authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    token = Authorization.replace("Bearer ", "")
    try:
        user = auth_client.auth.get_user(token)
        user_id = user.user.id
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # ✅ Create the new client record
    new_client = {
        "agent_id": user_id,
        "name": data.get("name"),
        "email": data.get("email"),
        "phone": data.get("phone"),
        "property": data.get("property"),
        "transactionType": data.get("transactionType"),
        "status": data.get("status", "pending"),
        "progress": data.get("progress", 0),
        "value": data.get("value", 0),
        "nextTask": data.get("nextTask"),
        "dueDate": data.get("dueDate"),
    }

    res = admin_client.table("clients").insert(new_client).execute()

    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to insert client")

    return res.data[0]
