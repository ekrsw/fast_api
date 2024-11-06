from fastapi import FastAPI
from . import database
from .routers import auth, items, users

# FastAPI アプリケーションのインスタンスを作成
app = FastAPI()

# データベースのテーブルを作成
# アプリケーション起動時に、Base クラスに基づいてデータベースにテーブルを作成します
database.Base.metadata.create_all(bind=database.engine)

# 各エンドポイントに対応するルーターをアプリケーションに登録
app.include_router(auth.router)  # 認証関連のルーター
app.include_router(items.router)  # アイテム関連のルーター
app.include_router(users.router)  # ユーザー関連のルーター
