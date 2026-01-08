from fastapi import APIRouter, Header, HTTPException
from supabase_client import admin_client, auth_client

router = APIRouter(prefix="/subscriptions", tags=["subscriptions"])

@router.get("/status")
def get_subscription_status(Authorization: str = Header(...)):
    token = Authorization.replace("Bearer ", "")
    user = auth_client.auth.get_user(token)
    
    res = admin_client.table("agents").select("plan").eq("id", user.user.id).single().execute()
    return res.data or {"plan": "free"}