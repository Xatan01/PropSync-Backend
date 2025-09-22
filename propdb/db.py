# db.py
import os
import databases
import sqlalchemy
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

database = databases.Database(DATABASE_URL)   # renamed
metadata = sqlalchemy.MetaData()

import propdb.models
