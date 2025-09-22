from fastapi import APIRouter, HTTPException
from propdb.db import database   # ✅ use `database` instead of `propdb`
from propdb import models

router = APIRouter(prefix="/clients", tags=["clients"])

# Get all clients
@router.get("/")
async def get_clients():
    query = models.clients.select()
    return await database.fetch_all(query)

# Get one client by ID
@router.get("/{client_id}")
async def get_client(client_id: int):
    query = models.clients.select().where(models.clients.c.id == client_id)
    client = await database.fetch_one(query)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")
    return client

# Create a client
@router.post("/")
async def create_client(client: dict):
    query = models.clients.insert().values(**client)
    client_id = await database.execute(query)
    return {**client, "id": client_id}
