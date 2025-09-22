import os
import time
import secrets
import base64
import hashlib
import hmac
import datetime
from typing import Optional, Dict, Tuple
import boto3
from botocore.exceptions import ClientError
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr
from utils.limiter import limiter   

# 🔥 NEW: import your DB + models
from propdb.db import database
from propdb import models

# ================================
# AWS Config
# ================================
AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-1")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
COGNITO_CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")

if not COGNITO_USER_POOL_ID or not COGNITO_CLIENT_ID:
    raise RuntimeError("Missing Cognito configuration")

cognito = boto3.client("cognito-idp", region_name=AWS_REGION)

# In-memory pending signup store (replace with Redis/DB in prod)
pending_signups: Dict[str, Tuple[str, float]] = {}

# ================================
# Helpers
# ================================
def _secret_hash(username: str) -> Optional[str]:
    if not COGNITO_CLIENT_SECRET:
        return None
    message = (username + COGNITO_CLIENT_ID).encode("utf-8")
    key = COGNITO_CLIENT_SECRET.encode("utf-8")
    dig = hmac.new(key, message, hashlib.sha256).digest()
    return base64.b64encode(dig).decode()

def _friendly_error(e: Exception) -> str:
    if isinstance(e, ClientError):
        code = e.response["Error"]["Code"]
        if code == "UsernameExistsException":
            return "An account with this email already exists. Try logging in."
        if code == "InvalidPasswordException":
            return "Password must have 8+ chars, upper/lowercase, number, and symbol."
        if code == "CodeMismatchException":
            return "That verification code is incorrect."
        if code == "ExpiredCodeException":
            return "That verification code expired. Request a new one."
        if code == "UserNotFoundException":
            return "We couldn’t find an account with that email."
        if code == "UserNotConfirmedException":
            return "Your account isn’t confirmed yet. Please check your email."
        if code == "NotAuthorizedException":
            msg = e.response["Error"].get("Message", "")
            if "Refresh Token has expired" in msg:
                return "Your session has expired. Please log in again."
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
    code: str
    pending_token: str

class ConfirmByEmailRequest(BaseModel):
    email: EmailStr
    code: str

class ResendConfirmationRequest(BaseModel):
    pending_token: str

class ResendByEmailRequest(BaseModel):
    email: EmailStr

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str
    email: Optional[EmailStr] = None

class LogoutRequest(BaseModel):
    access_token: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str

# ================================
# Router
# ================================
router = APIRouter(prefix="/auth", tags=["auth"])

# ---------- AUTH ROUTES ----------

@router.post("/register")
def register_user(request: Request, data: RegisterRequest):
    """Register a new user. No rate limit — Cognito enforces password rules."""
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

        pending_token = secrets.token_urlsafe(32)
        pending_signups[pending_token] = (data.email, time.time())

        return {
            "status": "pending_confirmation",
            "pending_token": pending_token,
            "message": "Please check your email for confirmation code.",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=_friendly_error(e))

@router.post("/confirm-signup")
@limiter.limit("1/30seconds")
async def confirm_signup(request: Request, data: ConfirmSignupRequest):
    """Confirm a new user with a pending_token + code."""
    try:
        if data.pending_token not in pending_signups:
            raise HTTPException(status_code=400, detail="Invalid or expired token.")
        username, created_time = pending_signups[data.pending_token]
        if time.time() - created_time > 900:
            del pending_signups[data.pending_token]
            raise HTTPException(status_code=400, detail="Pending token expired.")

        params = {"ClientId": COGNITO_CLIENT_ID, "Username": username, "ConfirmationCode": data.code}
        sh = _secret_hash(username)
        if sh:
            params["SecretHash"] = sh

        # Step 1: Confirm in Cognito
        cognito.confirm_sign_up(**params)

        # Step 2: Lookup Cognito user attributes (to get sub)
        resp = cognito.admin_get_user(
            UserPoolId=COGNITO_USER_POOL_ID,
            Username=username
        )
        sub = None
        name = None
        for attr in resp["UserAttributes"]:
            if attr["Name"] == "sub":
                sub = attr["Value"]
            if attr["Name"] == "name":
                name = attr["Value"]

        # Step 3: Insert into Postgres 🔥
        query = models.agents.insert().values(
            id=sub,
            name=name or "",
            email=username,
            member_since=datetime.datetime.utcnow(),
            plan="starter"
        )
        await database.execute(query)

        del pending_signups[data.pending_token]
        return {"status": "confirmed", "message": "Account confirmed."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=_friendly_error(e))
