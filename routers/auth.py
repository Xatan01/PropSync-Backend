# routers/auth.py
import os
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, EmailStr
from datetime import datetime, timezone

from supabase_client import admin_client, auth_client

router = APIRouter(prefix="/auth", tags=["auth"])

FRONTEND_URL = (os.getenv("FRONTEND_URL") or "http://localhost:5173").rstrip("/")
AGENT_DASHBOARD_URL = f"{FRONTEND_URL}/dashboard"
CLIENT_DASHBOARD_URL = f"{FRONTEND_URL}/client-dashboard"
RESET_PASSWORD_URL = f"{FRONTEND_URL}/reset-password"


# -------- Helpers --------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# -------- Schemas --------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str | None = None
    role: str = Query("agent", pattern="^(agent|client)$")  # optional param, defaults to agent


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    role: str = Query("agent", pattern="^(agent|client)$")  # expected role for this portal


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    role: str | None = None


class SetPasswordRequest(BaseModel):
    access_token: str
    refresh_token: str
    password: str


# -------- Routes --------
@router.post("/register")
def register_user(data: RegisterRequest):
    try:
        resp = auth_client.auth.sign_up(
            {
                "email": data.email,
                "password": data.password,
                "options": {
                    "data": {"name": data.name or "", "role": data.role},
                    # This is for email confirmation links (sign up flow)
                    "email_redirect_to": (
                        AGENT_DASHBOARD_URL if data.role == "agent" else CLIENT_DASHBOARD_URL
                    ),
                },
            }
        )

        if not resp.user:
            raise HTTPException(status_code=400, detail="Registration failed")

        return {
            "status": "pending_confirmation",
            "message": f"Please confirm your email to activate your {data.role} account.",
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login")
def login_user(data: LoginRequest):
    try:
        resp = auth_client.auth.sign_in_with_password(
            {"email": data.email, "password": data.password}
        )

        session = resp.session
        user = resp.user
        if not session or not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user_role = (user.user_metadata or {}).get("role")
        if user_role != data.role:
            raise HTTPException(
                status_code=403,
                detail=f"This account is a '{user_role or 'unknown'}' account.",
            )

        return {
            "status": "logged_in",
            "role": user_role,
            "name": (user.user_metadata or {}).get("name"),
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "expires_in": session.expires_in,
        }

    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/refresh")
def refresh_tokens(data: RefreshTokenRequest):
    """Refresh access tokens."""
    try:
        resp = auth_client.auth.refresh_session(data.refresh_token)
        session = resp.session
        if not session:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        return {
            "status": "refreshed",
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "expires_in": session.expires_in,
        }

    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/forgot-password")
def forgot_password(data: ForgotPasswordRequest):
    """Trigger Supabase password reset email."""
    try:
        role = (data.role or "agent").strip().lower()
        if role not in ("agent", "client"):
            role = "agent"
        redirect_to = f"{FRONTEND_URL}/reset-password?role={role}"
        auth_client.auth.reset_password_for_email(
            data.email,
            options={"redirect_to": redirect_to},
        )
        return {"status": "code_sent", "message": "Password reset email sent."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/set-password")
def set_password(data: SetPasswordRequest):
    """
    Client invite flow:
    - Frontend receives access_token + refresh_token from invite link (URL hash)
    - Frontend POSTs them here with the new password
    - We set session, update password, then mark public.clients as confirmed
    """
    if len(data.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    try:
        # 1) establish session as that invited user
        auth_client.auth.set_session(data.access_token, data.refresh_token)

        # 2) set the password for the currently-authenticated user
        auth_client.auth.update_user({"password": data.password})

        # 3) resolve user id so we can confirm the client row
        user_id = None
        try:
            u = auth_client.auth.get_user(data.access_token)
            user_id = getattr(getattr(u, "user", None), "id", None)
        except Exception:
            user_id = None

        if not user_id:
            raise HTTPException(status_code=400, detail="Could not resolve invited user from tokens")

        # 4) mark client row as confirmed
        admin_client.table("clients").update(
            {"invite_status": "confirmed", "confirmed_at": utc_now_iso()}
        ).eq("auth_user_id", user_id).execute()

        return {"status": "ok"}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to set password: {str(e)}")


@router.post("/logout")
def logout_user():
    """Sign out current user."""
    try:
        auth_client.auth.sign_out()
        return {"status": "signed_out", "message": "You’ve been signed out."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
