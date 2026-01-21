# routers/actions.py
from fastapi import APIRouter, Depends
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from supabase_client import admin_client
from utils.auth import get_current_user

router = APIRouter(prefix="/actions", tags=["actions"])


def parse_date(value: Optional[str]) -> Optional[datetime.date]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).date()
    except ValueError:
        return None


@router.get("/center")
def get_action_center(limit: int = 5, user: dict = Depends(get_current_user)):
    today = datetime.now(timezone.utc).date()
    upcoming_cutoff = today + timedelta(days=7)

    clients_res = (
        admin_client.table("clients")
        .select("id,name,invite_status,property,transaction_type")
        .eq("agent_id", user["sub"])
        .execute()
    )
    clients = clients_res.data or []

    timelines_res = (
        admin_client.table("client_timelines")
        .select("client_id,nodes")
        .eq("agent_id", user["sub"])
        .execute()
    )
    timelines_by_client = {row["client_id"]: (row.get("nodes") or []) for row in (timelines_res.data or [])}

    items: List[Dict[str, Any]] = []

    for client in clients:
        client_id = client["id"]
        name = client.get("name") or "Client"
        invite_status = client.get("invite_status") or "uninvited"

        if invite_status == "uninvited":
            items.append(
                {
                    "id": f"invite-{client_id}",
                    "client_id": client_id,
                    "type": "invite",
                    "title": "Invite client",
                    "description": f"{name} hasn't been invited yet.",
                    "priority": 3,
                }
            )
        elif invite_status == "pending":
            items.append(
                {
                    "id": f"invite-pending-{client_id}",
                    "client_id": client_id,
                    "type": "invite_pending",
                    "title": "Invite pending",
                    "description": f"Resend invite to {name}.",
                    "priority": 4,
                }
            )

        if not client.get("property") or not client.get("transaction_type"):
            items.append(
                {
                    "id": f"details-{client_id}",
                    "client_id": client_id,
                    "type": "deal_details",
                    "title": "Complete deal details",
                    "description": f"Add property or transaction type for {name}.",
                    "priority": 5,
                }
            )

        nodes = timelines_by_client.get(client_id)
        if not nodes:
            items.append(
                {
                    "id": f"timeline-{client_id}",
                    "client_id": client_id,
                    "type": "timeline_missing",
                    "title": "Create timeline",
                    "description": f"No timeline started for {name}.",
                    "priority": 6,
                }
            )
            continue

        overdue_candidates = []
        upcoming_candidates = []

        for node in nodes:
            node_data = node.get("data") if isinstance(node, dict) else {}
            due_date = parse_date(node_data.get("date"))
            if not due_date:
                continue
            if due_date < today:
                overdue_candidates.append((due_date, node_data.get("title") or "Milestone"))
            elif today <= due_date <= upcoming_cutoff:
                upcoming_candidates.append((due_date, node_data.get("title") or "Milestone"))

        if overdue_candidates:
            due_date, title = sorted(overdue_candidates, key=lambda x: x[0])[0]
            items.append(
                {
                    "id": f"overdue-{client_id}",
                    "client_id": client_id,
                    "type": "timeline_overdue",
                    "title": "Timeline overdue",
                    "description": f"{name}: {title} was due {due_date.isoformat()}",
                    "due_date": due_date.isoformat(),
                    "priority": 1,
                }
            )
        elif upcoming_candidates:
            due_date, title = sorted(upcoming_candidates, key=lambda x: x[0])[0]
            items.append(
                {
                    "id": f"upcoming-{client_id}",
                    "client_id": client_id,
                    "type": "timeline_upcoming",
                    "title": "Upcoming milestone",
                    "description": f"{name}: {title} due {due_date.isoformat()}",
                    "due_date": due_date.isoformat(),
                    "priority": 2,
                }
            )

    items.sort(key=lambda item: (item.get("priority", 99), item.get("due_date") or ""))
    return items[: max(limit, 0)]
