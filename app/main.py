# app/main.py
from fastapi import FastAPI
from . import database
from .routers import auth, items, users

# FastAPI アプリケーションのインスタンスを作成
app = FastAPI()

# データベースのテーブルを作成
database.Base.metadata.create_all(bind=database.engine)

# ルーターの登録
app.include_router(auth.router)
app.include_router(items.router)
app.include_router(users.router)
