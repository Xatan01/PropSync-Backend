# utils/auth.py
from fastapi import Header, HTTPException
from supabase_client import auth_client

def get_current_user(authorization: str = Header(...)):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")

    token = authorization.replace("Bearer ", "")

    try:
        user = auth_client.auth.get_user(token)
        return {
            "sub": user.user.id,
            "email": user.user.email,
            "user_metadata": user.user.user_metadata,
        }
    except Exception:
        raise HTTPException(status_code=401, detail="Session expired")
