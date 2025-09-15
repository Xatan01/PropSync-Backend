from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

# Load .env file
load_dotenv()

# Environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
    raise RuntimeError("Missing Supabase credentials in environment variables")

app = FastAPI()

# ✅ CORS: Allow only your frontend domain(s)
origins = [
    os.getenv("FRONTEND_URL", "http://localhost:3000"),
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import routers after env vars are loaded
from routers.auth import router as auth_router
app.include_router(auth_router)

@app.get("/")
def root():
    return {"message": "Backend is running 🚀"}