# utils/auth.py
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from supabase_client import supabase

security = HTTPBearer()

def verify_user(token=Depends(security)):
    """
    Verifies Supabase access_token and returns user info.
    This replaces the old Cognito get_current_user().
    """
    try:
        user = supabase.auth.get_user(token.credentials)
        if not user or not user.user:
            raise HTTPException(status_code=401, detail="Invalid user session.")
        return user.user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
