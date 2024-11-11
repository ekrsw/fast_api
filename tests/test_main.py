import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.main import on_startup
from app.database import Base
from sqlalchemy import inspect
from unittest.mock import patch

@pytest.mark.asyncio
async def test_on_startup_event(db_session: AsyncSession):
    """
    on_startup イベントが正しくテーブルを作成することを確認するテスト。
    
    Args:
        db_session (AsyncSession): テスト用のデータベースセッション（conftest.pyで提供）。
    """
    # テスト用エンジンを取得（既にテスト用のSQLiteエンジンが使用されている）
    test_engine = db_session.bind
    
    # テスト前にテーブルを削除してクリーンな状態にする
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    # app.database.engine をテスト用エンジンにパッチ
    with patch('app.database.engine', test_engine):
        await on_startup()
    
    # テーブルが作成されたことを確認
    async with test_engine.connect() as conn:
        # テーブル名を取得するヘルパー関数を定義
        def get_table_names(conn):
            inspector = inspect(conn)
            return inspector.get_table_names()
        
        # run_sync を使用して同期的にテーブル名を取得
        tables = await conn.run_sync(get_table_names)
        assert "users" in tables, "users テーブルが存在しません。"
        assert "items" in tables, "items テーブルが存在しません。"
