# routers/deals.py
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone

from supabase_client import admin_client
from utils.auth import get_current_user

router = APIRouter(prefix="/deals", tags=["deals"])


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DealPayload(BaseModel):
    property_type: Optional[str] = None
    transaction_type: Optional[str] = None
    status: Optional[str] = None
    value: Optional[float] = None


class DealNotePayload(BaseModel):
    body: str


@router.get("/clients/{client_id}/deal")
def get_client_deal(client_id: str, user: dict = Depends(get_current_user)):
    res = (
        admin_client.table("deals")
        .select("*")
        .eq("client_id", client_id)
        .eq("agent_id", user["sub"])
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Deal not found")
    return res.data[0]


@router.post("/clients/{client_id}/deal")
def upsert_client_deal(
    client_id: str, payload: DealPayload, user: dict = Depends(get_current_user)
):
    data = {
        "client_id": client_id,
        "agent_id": user["sub"],
        "property_type": payload.property_type,
        "transaction_type": payload.transaction_type,
        "status": payload.status,
        "value": payload.value,
        "updated_at": utc_now_iso(),
    }

    existing = (
        admin_client.table("deals")
        .select("id")
        .eq("client_id", client_id)
        .eq("agent_id", user["sub"])
        .execute()
    )

    if existing.data:
        res = (
            admin_client.table("deals")
            .update(data)
        .eq("id", existing.data[0]["id"])
        .execute()
        )
        if not res.data:
            raise HTTPException(status_code=500, detail="Failed to update deal")
        deal = res.data[0]
    else:
        data["created_at"] = utc_now_iso()
        res = admin_client.table("deals").insert(data).execute()
        if not res.data:
            raise HTTPException(status_code=500, detail="Failed to create deal")
        deal = res.data[0]

    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": client_id,
            "action": "updated deal",
            "description": "Updated deal details",
        }
    ).execute()

    return deal


@router.patch("/{deal_id}")
def update_deal(deal_id: str, payload: DealPayload, user: dict = Depends(get_current_user)):
    updates = payload.dict(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No valid fields to update")
    updates["updated_at"] = utc_now_iso()

    res = (
        admin_client.table("deals")
        .update(updates)
        .eq("id", deal_id)
        .eq("agent_id", user["sub"])
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Deal not found")

    deal = res.data[0]

    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": deal.get("client_id"),
            "action": "updated deal",
            "description": "Updated deal details",
        }
    ).execute()

    return deal


@router.get("/{deal_id}/notes")
def list_deal_notes(deal_id: str, user: dict = Depends(get_current_user)):
    deal = (
        admin_client.table("deals")
        .select("id")
        .eq("id", deal_id)
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    if not deal.data:
        raise HTTPException(status_code=404, detail="Deal not found")

    res = (
        admin_client.table("deal_notes")
        .select("*")
        .eq("deal_id", deal_id)
        .order("created_at", desc=True)
        .execute()
    )
    return res.data or []


@router.post("/{deal_id}/notes")
def add_deal_note(
    deal_id: str, payload: DealNotePayload, user: dict = Depends(get_current_user)
):
    deal = (
        admin_client.table("deals")
        .select("id, client_id")
        .eq("id", deal_id)
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    if not deal.data:
        raise HTTPException(status_code=404, detail="Deal not found")

    res = admin_client.table("deal_notes").insert(
        {
            "deal_id": deal_id,
            "author_id": user["sub"],
            "body": payload.body,
            "created_at": utc_now_iso(),
        }
    ).execute()
    if not res.data:
        raise HTTPException(status_code=500, detail="Failed to add note")

    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": deal.data.get("client_id"),
            "action": "added deal note",
            "description": "Added a deal note",
        }
    ).execute()

    return res.data[0]


@router.patch("/{deal_id}/notes/{note_id}")
def update_deal_note(
    deal_id: str, note_id: str, payload: DealNotePayload, user: dict = Depends(get_current_user)
):
    deal = (
        admin_client.table("deals")
        .select("id, client_id")
        .eq("id", deal_id)
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    if not deal.data:
        raise HTTPException(status_code=404, detail="Deal not found")

    res = (
        admin_client.table("deal_notes")
        .update({"body": payload.body})
        .eq("id", note_id)
        .eq("deal_id", deal_id)
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Note not found")

    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": deal.data.get("client_id"),
            "action": "updated deal note",
            "description": "Updated a deal note",
        }
    ).execute()

    return res.data[0]


@router.delete("/{deal_id}/notes/{note_id}")
def delete_deal_note(deal_id: str, note_id: str, user: dict = Depends(get_current_user)):
    deal = (
        admin_client.table("deals")
        .select("id, client_id")
        .eq("id", deal_id)
        .eq("agent_id", user["sub"])
        .single()
        .execute()
    )
    if not deal.data:
        raise HTTPException(status_code=404, detail="Deal not found")

    res = (
        admin_client.table("deal_notes")
        .delete()
        .eq("id", note_id)
        .eq("deal_id", deal_id)
        .execute()
    )
    if not res.data:
        raise HTTPException(status_code=404, detail="Note not found")

    admin_client.table("activities").insert(
        {
            "agent_id": user["sub"],
            "client_id": deal.data.get("client_id"),
            "action": "deleted deal note",
            "description": "Deleted a deal note",
        }
    ).execute()

    return {"status": "deleted"}
