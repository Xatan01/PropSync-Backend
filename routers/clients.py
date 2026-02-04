# routers/clients.py
import os
from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any
from datetime import datetime, timezone
from uuid import UUID

from supabase_client import admin_client
from utils.auth import get_current_user

router = APIRouter(prefix="/clients", tags=["clients"])

# Keep in sync with your Supabase redirect allowlist.
FRONTEND_URL = (os.getenv("FRONTEND_URL") or "http://localhost:5173").rstrip("/")
CLIENT_SET_PASSWORD_URL = f"{FRONTEND_URL}/client/set-password"

# ----------------------------
# Helpers
# ----------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ----------------------------
# List / Create Clients
# Support BOTH /clients and /clients/ to avoid 307 redirects
# ----------------------------
@router.get("")
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


@router.post("")
@router.post("/")
def create_client(data: Dict[str, Any], user: dict = Depends(get_current_user)):
    new_client = {
        "agent_id": user["sub"],
        "name": data.get("name"),
        "email": data.get("email"),
        "phone": data.get("phone"),
        "property": data.get("property"),
        "transaction_type": data.get("transactionType") or data.get("transaction_type"),
        "status": "pending",
        "value": 0,
        "invite_status": "uninvited",
    }

    res = admin_client.table("clients").insert(new_client).execute()
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to create client")

    client = res.data[0]

    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": client["id"],
            "action": "created client",
            "description": f"Added new client {client['name']}",
        }
    ).execute()

    return client


# ----------------------------
# Activities
# IMPORTANT: keep this BEFORE /{client_id} routes
# ----------------------------
@router.get("/activity")
def list_activities(user: dict = Depends(get_current_user)):
    res = (
        admin_client.table("activities")
        .select("*")
        .eq("agent_id", user["sub"])
        .order("created_at", desc=True)
        .execute()
    )
    return res.data or []


# ----------------------------
# Get single client
# Use UUID type so invalid ids won't blow up as DB errors
# ----------------------------
@router.patch("/{client_id}")
def update_client(client_id: UUID, data: Dict[str, Any], user: dict = Depends(get_current_user)):
    allowed_fields = {
        "name",
        "email",
        "phone",
        "property",
        "transaction_type",
        "status",
        "value",
        "invite_status",
    }
    updates = {k: v for k, v in data.items() if k in allowed_fields}
    if "transactionType" in data:
        updates["transaction_type"] = data.get("transactionType")

    if not updates:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    existing = (
        admin_client.table("clients")
        .select("email, auth_user_id")
        .eq("id", str(client_id))
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    if not existing.data:
        raise HTTPException(status_code=404, detail="Client not found")

    existing_email = (existing.data.get("email") or "").strip().lower()
    new_email = (updates.get("email") or "").strip().lower()
    auth_user_id = existing.data.get("auth_user_id")
    if new_email and new_email != existing_email:
        if auth_user_id:
            try:
                admin_client.auth.admin.update_user_by_id(
                    auth_user_id,
                    {"email": new_email, "email_confirm": False},
                )
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Failed to update auth email: {str(e)}")
        try:
            admin_client.auth.reset_password_for_email(
                new_email,
                options={"redirect_to": CLIENT_SET_PASSWORD_URL},
            )
        except Exception:
            pass
        updates.update(
            {
                "invite_status": "uninvited",
                "invited_at": None,
                "confirmed_at": None,
            }
        )

    res = (
        admin_client.table("clients")
        .update(updates)
        .eq("id", str(client_id))
        .eq("agent_id", user["sub"])
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Client not found")

    client = res.data[0]

    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": client["id"],
            "action": "updated client",
            "description": f"Updated client {client.get('name') or ''}".strip(),
        }
    ).execute()

    return client


@router.delete("/{client_id}")
def delete_client(client_id: UUID, user: dict = Depends(get_current_user)):
    res = (
        admin_client.table("clients")
        .delete()
        .eq("id", str(client_id))
        .eq("agent_id", user["sub"])
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Client not found")

    client = res.data[0]
    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": client["id"],
            "action": "deleted client",
            "description": f"Deleted client {client.get('name') or ''}".strip(),
        }
    ).execute()

    return {"status": "deleted"}


@router.get("/{client_id}")
def get_client(client_id: UUID, user: dict = Depends(get_current_user)):
    res = (
        admin_client.table("clients")
        .select("*")
        .eq("id", str(client_id))
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Client not found")
    return res.data


# ----------------------------
# Invite client (create Supabase Auth user + send email)
# ----------------------------
@router.post("/invite/{client_id}")
def invite_client(client_id: UUID, user: dict = Depends(get_current_user)):
    # 1) verify client belongs to agent
    client_res = (
        admin_client.table("clients")
        .select("*")
        .eq("id", str(client_id))
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    if not client_res.data:
        raise HTTPException(status_code=404, detail="Client not found")

    client = client_res.data
    if not client.get("email"):
        raise HTTPException(status_code=400, detail="Client email is missing")

    email = client["email"]
    name = client.get("name") or "Client"

    created_user_id = None

    # 2) Prefer "invite_user_by_email" if your supabase-py supports it
    #    This is the most "email invite link" behavior.
    try:
        # Some supabase-py versions expose:
        # admin_client.auth.admin.invite_user_by_email(email, options={...})
        invited = admin_client.auth.admin.invite_user_by_email(
            email,
            options={
                "redirect_to": CLIENT_SET_PASSWORD_URL,
                "data": {"role": "client", "name": name},
            },
        )
        # invited.user.id exists on some versions
        created_user_id = getattr(getattr(invited, "user", None), "id", None)

    except Exception as e:
        msg = str(e)
        if "already been registered" in msg or "already registered" in msg:
            admin_client.table("clients").update(
                {
                    "invite_status": "pending",
                    "invited_at": utc_now_iso(),
                }
            ).eq("id", str(client_id)).execute()
            try:
                admin_client.auth.reset_password_for_email(
                    email,
                    options={"redirect_to": CLIENT_SET_PASSWORD_URL},
                )
            except Exception:
                pass
            return {"status": "already_registered"}
        else:
            raise HTTPException(status_code=500, detail=f"Invite failed: {msg}")

    # 4) Update clients table invite status
    update_fields = {
        "invite_status": "pending",
        "invited_at": utc_now_iso(),
    }
    if created_user_id:
        update_fields["auth_user_id"] = created_user_id

    admin_client.table("clients").update(update_fields).eq("id", str(client_id)).execute()

    # 5) Log activity
    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": str(client_id),
            "action": "sent invite",
            "description": f"Sent invite to {name} ({email})",
        }
    ).execute()

    return {"status": "invited", "auth_user_id": created_user_id}
