from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse
from utils.limiter import limiter

from propdb.db import database, metadata   # ✅ renamed properly
from propdb import models
from routers.auth import router as auth_router
from routers.clients import router as clients_router

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="PropSync Backend")
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc):
    return JSONResponse(status_code=429, content={"detail": "Too many requests"})

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    await database.connect()   # ✅ fixed

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()   # ✅ fixed

# Routers
app.include_router(auth_router)
app.include_router(clients_router)

@app.get("/")
def root():
    return {"message": "Backend running 🚀"}
