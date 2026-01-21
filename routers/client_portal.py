from fastapi import APIRouter, Header, HTTPException, UploadFile, File
from datetime import datetime
from supabase_client import admin_client, auth_client

router = APIRouter(prefix="/client", tags=["client"])


def get_client(token: str):
    user = auth_client.auth.get_user(token)
    uid = user.user.id

    res = admin_client.table("clients").select("*").eq("auth_user_id", uid).single().execute()
    if not res.data:
        raise HTTPException(status_code=404, detail="Client record not found")
    return res.data


@router.get("/me")
def my_profile(Authorization: str = Header(...)):
    client = get_client(Authorization.replace("Bearer ", ""))
    return client


@router.get("/timeline")
def my_timeline(Authorization: str = Header(...)):
    client = get_client(Authorization.replace("Bearer ", ""))
    res = admin_client.table("timeline").select("*").eq("client_id", client["id"]).order("created_at", desc=True).execute()
    return res.data or []


@router.post("/upload")
def upload_doc(file: UploadFile = File(...), Authorization: str = Header(...)):
    client = get_client(Authorization.replace("Bearer ", ""))
    path = f"{client['id']}/{datetime.utcnow().timestamp()}_{file.filename}"

    admin_client.storage.from_("propsync-docs").upload(path, file.file.read())

    admin_client.table("documents").insert({
        "client_id": client["id"],
        "file_path": path,
        "file_name": file.filename,
        "uploaded_by": client["auth_user_id"]
    }).execute()

    admin_client.table("timeline").insert({
        "client_id": client["id"],
        "message": f"Client uploaded {file.filename}",
        "created_by": client["auth_user_id"]
    }).execute()

    return {"status": "uploaded"}
