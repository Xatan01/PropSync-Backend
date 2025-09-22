from fastapi import APIRouter

router = APIRouter(prefix="/clients", tags=["clients"])

@router.get("/")
async def placeholder_clients():
    return {"message": "Clients endpoint not implemented yet"}
