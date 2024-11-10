import pytest
import pytest_asyncio
import uuid
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.dependencies import get_db
from app.database import Base


# テスト用データベースURL（SQLiteのメモリデータベースを使用）
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

# 非同期エンジンとセッションファクトリの設定
engine = create_async_engine(TEST_DATABASE_URL, echo=True, future=True)
TestingSessionLocal = sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)

@pytest_asyncio.fixture(scope="session")
async def setup_db():
    # テスト用データベースのテーブルを作成
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # テスト後にテーブルを削除
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest_asyncio.fixture
async def db_session(setup_db):
    # 非同期セッションを生成
    async with TestingSessionLocal() as session:
        yield session

@pytest_asyncio.fixture
def override_get_db(db_session):
    # 依存関係をオーバーライド
    async def _override_get_db():
        yield db_session
    app.dependency_overrides[get_db] = _override_get_db
    yield
    app.dependency_overrides.pop(get_db, None)

@pytest_asyncio.fixture
async def client(override_get_db):
    # AsyncClientを使用してテストクライアントを作成
    async with AsyncClient(app=app, base_url="http://test") as c:
        yield c

@pytest.fixture
def unique_username():
    """ユニークなユーザー名を生成するフィクスチャ"""
    return f"user_{uuid.uuid4()}"

@pytest.fixture
def unique_item_name():
    """ユニークなアイテム名を生成するフィクスチャ"""
    return f"item_{uuid.uuid4()}"
