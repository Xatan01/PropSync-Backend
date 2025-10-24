# routers/auth.py
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, EmailStr
from supabase_client import admin_client, auth_client

router = APIRouter(prefix="/auth", tags=["auth"])


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


# -------- Routes --------

@router.post("/register")
def register_user(data: RegisterRequest):
    """Register a new user (agent/client) and send confirmation email."""
    try:
        # ✅ Include role in user metadata
        resp = auth_client.auth.sign_up({
            "email": data.email,
            "password": data.password,
            "options": {
                "data": {
                    "name": data.name or "",
                    "role": data.role  # 👈 stored in Supabase user_metadata
                },
                "email_redirect_to": (
                    "http://localhost:5173/dashboard"
                    if data.role == "agent"
                    else "http://localhost:5173/client-dashboard"
                ),
            },
        })

        user = resp.user
        if not user:
            raise HTTPException(status_code=400, detail="Registration failed")

        # ✅ Insert into the correct app table
        table_name = "agents" if data.role == "agent" else "clients"
        admin_client.table(table_name).insert({
            "id": user.id,
            "name": data.name or "",
            "email": data.email,
            "plan": "starter" if data.role == "agent" else None,
        }).execute()

        return {
            "status": "pending_confirmation",
            "message": f"Please confirm your email to activate your {data.role} account."
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login")
def login_user(data: LoginRequest):
    """Email-password login (with role check)."""
    try:
        resp = auth_client.auth.sign_in_with_password({
            "email": data.email,
            "password": data.password,
        })

        session = resp.session
        user = resp.user
        if not session or not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # ✅ Role validation
        user_role = user.user_metadata.get("role") if hasattr(user, "user_metadata") else None
        if user_role != data.role:
            raise HTTPException(
                status_code=403,
                detail=f"This account is a '{user_role or 'unknown'}' account. Please log in via the correct portal."
            )

        return {
            "status": "logged_in",
            "role": user_role,
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "expires_in": session.expires_in,
            "token_type": "Bearer",
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
    """Trigger Supabase password reset email (safe response)."""
    try:
        auth_client.auth.reset_password_for_email(
            data.email,
            options={"redirect_to": "http://localhost:5173/reset-password"}
        )

        # ✅ Always return a neutral message (prevents email enumeration)
        return {
            "status": "code_sent",
            "message": "If this email is registered, you'll receive a reset link shortly."
        }

    except Exception as e:
        # You can still log internally for debugging if needed
        print("Forgot password error:", e)
        # But respond with the same neutral message to the client
        return {
            "status": "code_sent",
            "message": "If this email is registered, you'll receive a reset link shortly."
        }



@router.post("/logout")
def logout_user():
    """Sign out current user."""
    try:
        auth_client.auth.sign_out()
        return {"status": "signed_out", "message": "You’ve been signed out."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
