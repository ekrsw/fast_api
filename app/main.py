from fastapi import FastAPI
from . import database
from .routers import auth, items, users

app = FastAPI()


@app.on_event("startup")
async def on_startup():
    """
    アプリケーションの起動時にデータベースのテーブルを作成します。

    このイベントハンドラーは、アプリケーションが起動する際に呼び出され、
    データベース接続を確立し、全てのテーブルを自動的に作成します。
    """
    async with database.engine.begin() as conn:
        await conn.run_sync(database.Base.metadata.create_all)


# ルーターの登録
app.include_router(auth.router)
app.include_router(items.router)
app.include_router(users.router)
