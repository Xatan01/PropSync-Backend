import jwt
import os
from fastapi import Header, HTTPException

SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET")

def get_current_user(authorization: str = Header(...)):
    """
    Decodes the JWT locally. If the token is expired or fake, 
    FastAPI blocks the request before it even touches your database logic.
    """
    try:
        token = authorization.replace("Bearer ", "")
        payload = jwt.decode(
            token, 
            SUPABASE_JWT_SECRET, 
            algorithms=["HS256"], 
            audience="authenticated"
        )
        # Returns user UUID and metadata safely
        return payload 
    except Exception:
        raise HTTPException(status_code=401, detail="Session expired")