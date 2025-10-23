# supabase_client.py
from supabase import create_client, Client
import os
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")

if not SUPABASE_URL or not SUPABASE_SERVICE_KEY or not SUPABASE_ANON_KEY:
    raise RuntimeError("Missing Supabase credentials in .env")

# 🔐 Full-access client (for inserting to tables like agents)
admin_client: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# 🔓 Public client (for auth actions like login, reset password, etc.)
auth_client: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
