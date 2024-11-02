import os
from sqlalchemy.orm import Session
from . import models, schemas, crud, auth, database
from dotenv import load_dotenv

load_dotenv()

def create_initial_admin():
    db = database.SessionLocal()
    username = os.getenv("INITIAL_ADMIN_USERNAME")
    password = os.getenv("INITIAL_ADMIN_PASSWORD")
    if not username or not password:
        print("INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD must be set in .env")
        return
    existing_admin = crud.get_user_by_username(db, username=username)
    if existing_admin:
        print("Admin user already exists.")
        return
    admin_user = crud.create_user(
        db, 
        schemas.UserCreate(username=username, password=password), 
        is_admin=True
    )
    print(f"Admin user created: {admin_user.username}")

if __name__ == "__main__":
    create_initial_admin()
