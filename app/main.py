# app/main.py
from fastapi import FastAPI
from . import database
from .routers import auth, items, users

app = FastAPI()

# イベントハンドラーを使用してテーブルを作成
@app.on_event("startup")
async def on_startup():
    async with database.engine.begin() as conn:
        await conn.run_sync(database.Base.metadata.create_all)

# ルーターの登録
app.include_router(auth.router)
app.include_router(items.router)
app.include_router(users.router)
