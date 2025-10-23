# routers/auth.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from supabase_client import admin_client, auth_client

router = APIRouter(prefix="/auth", tags=["auth"])


# -------- Schemas --------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str | None = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr


# -------- Routes --------

@router.post("/register")
def register_user(data: RegisterRequest):
    """Register a new agent and send magic confirmation email."""
    try:
        resp = auth_client.auth.sign_up({
            "email": data.email,
            "password": data.password,
            "options": {
                "data": {"name": data.name or ""},
                "email_redirect_to": "http://localhost:5173/dashboard"
            }
        })
        user = resp.user
        if not user:
            raise HTTPException(status_code=400, detail="Registration failed")

        # Insert into agents table using admin client
        admin_client.table("agents").insert({
            "id": user.id,
            "name": data.name or "",
            "email": data.email,
            "plan": "starter",
        }).execute()

        return {
            "status": "pending_confirmation",
            "message": "Please check your email for the confirmation link (auto-login)."
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login")
def login_user(data: LoginRequest):
    """Email-password login."""
    try:
        resp = auth_client.auth.sign_in_with_password({
            "email": data.email,
            "password": data.password
        })
        session = resp.session
        if not session:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        return {
            "status": "logged_in",
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "expires_in": session.expires_in,
            "token_type": "Bearer"
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
            "expires_in": session.expires_in
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/forgot-password")
def forgot_password(data: ForgotPasswordRequest):
    """Trigger Supabase password reset email."""
    try:
        auth_client.auth.reset_password_for_email(
            data.email,
            options={"redirect_to": "http://localhost:5173/reset-password"}
        )
        return {"status": "code_sent", "message": "Password reset email sent."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/logout")
def logout_user():
    """Sign out current user."""
    try:
        auth_client.auth.sign_out()
        return {"status": "signed_out", "message": "You’ve been signed out."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
