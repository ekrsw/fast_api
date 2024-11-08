import pytest_asyncio
import sys
import os

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database import Base
from app.config import Settings

# プロジェクトルートをPythonパスに追加
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# テスト用設定のオーバーライド
settings = Settings(
    database_user="test_admin",
    database_password="test_password",
    database_name="test_database",
    secret_key="test_secret_key",
    refresh_secret_key="test_refresh_secret_key",
    initial_admin_username="test_admin",
    initial_admin_password="test_admin_password",
    # 必要に応じて他の設定もオーバーライド
)

# テスト用データベースURL
TEST_DATABASE_URL = (
    f"postgresql+asyncpg://{settings.database_user}:"
    f"{settings.database_password}@{settings.database_host}:"
    f"{settings.database_port}/{settings.database_name}"
)

# 非同期エンジンの作成
test_engine = create_async_engine(TEST_DATABASE_URL, echo=False, future=True)

# テスト用セッションファクトリ
TestingSessionLocal = sessionmaker(
    bind=test_engine, class_=AsyncSession, expire_on_commit=False
)

# テスト用データベースのセットアップとクリーンアップ
@pytest_asyncio.fixture(scope="session", autouse=True)
async def prepare_database():
    # テストデータベースのテーブル作成
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    # テスト後にテーブルを削除
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

# データベースセッションのフィクスチャ
@pytest_asyncio.fixture
async def db_session():
    async with TestingSessionLocal() as session:
        yield session
        await session.rollback()

# HTTPクライアントのフィクスチャ
@pytest_asyncio.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
