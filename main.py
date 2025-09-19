from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# 🚦 SlowAPI imports
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse

load_dotenv()

# ================================
# App setup
# ================================
limiter = Limiter(key_func=get_remote_address)

app = FastAPI()
app.state.limiter = limiter

# Handle rate limit errors nicely
@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc):
    return JSONResponse(
        status_code=429,
        content={"detail": "⏳ Too many requests. Please wait before trying again."},
    )

# ================================
# CORS
# ================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================================
# Routers
# ================================
from routers.auth import router as auth_router
app.include_router(auth_router)

# ================================
# Root health check
# ================================
@app.get("/")
def root():
    return {"message": "Backend is running 🚀"}