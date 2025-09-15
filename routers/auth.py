from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
import os

# Load Supabase credentials from env vars
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    raise RuntimeError("Missing Supabase credentials in environment variables")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

router = APIRouter(prefix="/auth", tags=["auth"])

# ---------------------------
# Pydantic Models
# ---------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str | None = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

# ---------------------------
# Routes
# ---------------------------

@router.post("/register")
def register_user(data: RegisterRequest):
    """
    Register a new user with email + password + optional name.
    Name is stored in Supabase user_metadata.
    """
    try:
        result = supabase.auth.sign_up({
            "email": data.email,
            "password": data.password,
            "data": {"name": data.name} if data.name else {}
        })
        if result.user is None:
            raise HTTPException(status_code=400, detail="User could not be created")
        return {"message": "User registered successfully", "user": result.user}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/login")
def login(data: LoginRequest):
    """
    Login user with email + password.
    """
    try:
        result = supabase.auth.sign_in_with_password(
            {"email": data.email, "password": data.password}
        )
        if not result.session:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return {
            "access_token": result.session.access_token,
            "refresh_token": result.session.refresh_token,
            "token_type": "bearer",
            "user": result.user,
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))