import os
import time
import secrets
import base64
import hashlib
import hmac
from typing import Optional, Dict, Tuple
import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, Field

# ================================
# AWS Config
# ================================
AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-1")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
COGNITO_CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")  # optional

if not COGNITO_USER_POOL_ID or not COGNITO_CLIENT_ID:
    raise RuntimeError("Missing Cognito configuration")

cognito = boto3.client("cognito-idp", region_name=AWS_REGION)

# In-memory pending signup store (replace with Redis/DB in prod)
pending_signups: Dict[str, Tuple[str, float]] = {}

# ================================
# Helpers
# ================================
def _secret_hash(username: str) -> Optional[str]:
    """Compute SECRET_HASH iff the app client has a secret."""
    if not COGNITO_CLIENT_SECRET:
        return None
    message = (username + COGNITO_CLIENT_ID).encode("utf-8")
    key = COGNITO_CLIENT_SECRET.encode("utf-8")
    dig = hmac.new(key, message, hashlib.sha256).digest()
    return base64.b64encode(dig).decode()


def _friendly_error(e: Exception) -> str:
    """Map Cognito errors to user-friendly messages."""
    if isinstance(e, ClientError):
        code = e.response["Error"]["Code"]
        if code == "UsernameExistsException":
            return "An account with this email already exists. Try logging in."
        if code == "InvalidPasswordException":
            return "Password must have 8+ chars, upper/lowercase, number, and symbol."
        if code == "CodeMismatchException":
            return "That verification code is incorrect."
        if code == "ExpiredCodeException":
            return "That verification code expired. Please request a new one."
        if code == "UserNotFoundException":
            return "We couldn’t find an account with that email."
        if code == "UserNotConfirmedException":
            return "Your account isn’t confirmed yet. Please check your email."
        if code == "NotAuthorizedException":
            return "Incorrect email or password."
    return "Something went wrong. Please try again."

# ================================
# Schemas
# ================================
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None

class ConfirmSignupRequest(BaseModel):
    code: str = Field(..., min_length=1)
    pending_token: str = Field(..., min_length=10)

class ResendConfirmationRequest(BaseModel):
    pending_token: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

# ================================
# Router
# ================================
router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register")
def register_user(data: RegisterRequest):
    try:
        params = {
            "ClientId": COGNITO_CLIENT_ID,
            "Username": data.email,
            "Password": data.password,
            "UserAttributes": [{"Name": "email", "Value": data.email}],
        }
        if data.name:
            params["UserAttributes"].append({"Name": "name", "Value": data.name})

        sh = _secret_hash(data.email)
        if sh:
            params["SecretHash"] = sh

        cognito.sign_up(**params)

        # Store email temporarily with pending token (10 min expiry)
        token = secrets.token_urlsafe(32)
        pending_signups[token] = (data.email, time.time() + 600)

        return {
            "status": "pending_confirmation",
            "message": "Check your email for the verification code.",
            "pending_token": token,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=_friendly_error(e))


@router.post("/confirm-signup")
def confirm_signup(data: ConfirmSignupRequest):
    entry = pending_signups.get(data.pending_token)
    if not entry:
        raise HTTPException(status_code=400, detail="Confirmation session expired. Please register again.")

    email, expiry = entry
    if time.time() > expiry:
        del pending_signups[data.pending_token]
        raise HTTPException(status_code=400, detail="Confirmation token expired. Please register again.")

    try:
        params = {
            "ClientId": COGNITO_CLIENT_ID,
            "Username": email,
            "ConfirmationCode": data.code,
        }
        sh = _secret_hash(email)
        if sh:
            params["SecretHash"] = sh

        cognito.confirm_sign_up(**params)
        del pending_signups[data.pending_token]
        return {"status": "confirmed", "message": "Email confirmed. You can now log in."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=_friendly_error(e))


@router.post("/resend-confirmation")
def resend_confirmation(data: ResendConfirmationRequest):
    entry = pending_signups.get(data.pending_token)
    if not entry:
        raise HTTPException(status_code=400, detail="Confirmation session expired. Please register again.")

    email, expiry = entry
    if time.time() > expiry:
        del pending_signups[data.pending_token]
        raise HTTPException(status_code=400, detail="Confirmation token expired. Please register again.")

    try:
        params = {"ClientId": COGNITO_CLIENT_ID, "Username": email}
        sh = _secret_hash(email)
        if sh:
            params["SecretHash"] = sh

        cognito.resend_confirmation_code(**params)
        return {"status": "code_sent", "message": "We’ve sent a new verification code to your email."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=_friendly_error(e))


@router.post("/login")
def login_user(data: LoginRequest):
    try:
        params = {
            "ClientId": COGNITO_CLIENT_ID,
            "AuthFlow": "USER_PASSWORD_AUTH",
            "AuthParameters": {
                "USERNAME": data.email,
                "PASSWORD": data.password,
            },
        }
        sh = _secret_hash(data.email)
        if sh:
            params["AuthParameters"]["SECRET_HASH"] = sh

        resp = cognito.initiate_auth(**params)

        ar = resp.get("AuthenticationResult")
        if not ar:
            raise HTTPException(status_code=401, detail="Login failed. Extra verification may be required.")

        return {
            "status": "authenticated",
            "access_token": ar["AccessToken"],
            "id_token": ar.get("IdToken"),
            "refresh_token": ar.get("RefreshToken"),
            "expires_in": ar.get("ExpiresIn"),
            "token_type": ar.get("TokenType", "Bearer"),
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=_friendly_error(e))