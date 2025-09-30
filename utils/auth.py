import os
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from jwt import PyJWKClient

AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-1")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")

if not COGNITO_USER_POOL_ID:
    raise RuntimeError("Missing COGNITO_USER_POOL_ID in env")

# Cognito JWKS (JSON Web Key Set) URL
JWKS_URL = f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"

# Security scheme for FastAPI
security = HTTPBearer()

# Setup PyJWKClient once (cached keys)
jwks_client = PyJWKClient(JWKS_URL)

def get_current_user(token=Depends(security)):
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token.credentials).key
        payload = jwt.decode(
            token.credentials,
            signing_key,
            algorithms=["RS256"],
            options={"verify_aud": False},  # skip audience check
        )
        return payload  # includes "sub", "email", etc.
    except Exception as e:
        print("❌ JWT decode failed:", e)
        raise HTTPException(status_code=401, detail="Invalid or expired token")