# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers.auth import router as auth_router
from routers.clients import router as clients_router
from routers.deals import router as deals_router
from routers.timeline import router as timeline_router
from routers.subscriptions import router as subscriptions_router
from routers.actions import router as actions_router
from routers.documents import router as documents_router
from routers.client_portal import router as client_portal_router

app = FastAPI(title="PropSync Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://prop-sync-frontend.vercel.app"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REGISTER ALL ROUTERS
app.include_router(auth_router)
app.include_router(clients_router)
app.include_router(deals_router)
app.include_router(timeline_router)
app.include_router(subscriptions_router)
app.include_router(actions_router)
app.include_router(documents_router)
app.include_router(client_portal_router)


@app.get("/")
def root():
    return {"message": "PropSync backend running"}
