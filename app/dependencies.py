from .database import AsyncSessionLocal
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends


async def get_db() -> AsyncSession:
    """
    データベースセッションを取得するための依存関数です。

    この関数は、非同期セッションファクトリ `AsyncSessionLocal` を使用して
    データベースセッションを生成し、FastAPIの依存関係として提供します。
    リクエストごとに新しいセッションを作成し、リクエスト終了時にセッションをクローズします。

    Yields
    ------
    AsyncSession
        使用中のデータベースセッションオブジェクト。
    """
    async with AsyncSessionLocal() as session:
        yield session
