from fastapi import APIRouter, Depends
from propdb.db import database
from propdb import models
from utils.auth import get_current_user

router = APIRouter(prefix="/clients", tags=["clients"])

@router.get("")
async def list_clients(user=Depends(get_current_user)):
    # Only return clients for this agent
    query = models.clients.select().where(models.clients.c.agent_id == user["sub"])
    return await database.fetch_all(query)

@router.post("")
async def create_client(data: dict, user=Depends(get_current_user)):
    # Add a new client under this agent
    query = models.clients.insert().values(
        agent_id=user["sub"],
        name=data.get("name"),
        email=data.get("email"),
        phone=data.get("phone"),
        property=data.get("property"),
        transactionType=data.get("transactionType"),
        status=data.get("status", "pending"),
        progress=data.get("progress", 0),
        value=data.get("value", 0),
        nextTask=data.get("nextTask"),
        dueDate=data.get("dueDate"),
    )
    new_id = await database.execute(query)
    return {**data, "id": new_id, "agent_id": user["sub"]}