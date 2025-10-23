# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers.auth import router as auth_router

app = FastAPI(title="PropSync Backend")

# CORS for your frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # update if deployed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth_router)

@app.get("/")
def root():
    return {"message": "PropSync backend running 🚀"}
