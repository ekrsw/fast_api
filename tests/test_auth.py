import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app import crud, schemas

@pytest.mark.asyncio
async def test_login_for_access_token(client: AsyncClient, db_session: AsyncSession):
    """
    ログインしてアクセストークンを取得するテスト。
    """
    # 初期管理者ユーザーの作成
    user_create = schemas.UserCreate(
        username="test_admin",
        password="test_admin_password"
    )
    await crud.create_user(db=db_session, user=user_create, is_admin=True)
    
    # ログインリクエストの送信
    response = await client.post(
        "/auth/token",
        data={"username": user_create.username, "password": user_create.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "refresh_token" in data

@pytest.mark.asyncio
async def test_login_with_invalid_credentials(client: AsyncClient, db_session: AsyncSession):
    """
    無効な資格情報でのログインテスト。
    """
    # ログインリクエストの送信（存在しないユーザー）
    response = await client.post(
        "/auth/token",
        data={"username": "nonexistent", "password": "wrongpassword"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 401
    data = response.json()
    assert data["detail"] == "Incorrect username or password"

@pytest.mark.asyncio
async def test_refresh_access_token(client: AsyncClient, db_session: AsyncSession):
    """
    リフレッシュトークンを使用してアクセストークンを更新するテスト。
    """
    # 初期管理者ユーザーの作成
    user_create = schemas.UserCreate(
        username="test_admin",
        password="test_admin_password"
    )
    await crud.create_user(db=db_session, user=user_create, is_admin=True)
    
    # トークンの取得
    response = await client.post(
        "/auth/token",
        data={"username": user_create.username, "password": user_create.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 200
    tokens = response.json()
    refresh_token = tokens["refresh_token"]
    
    # リフレッシュトークンを使用して新しいアクセストークンを取得
    response = await client.post(
        "/auth/refresh",
        headers={"Refresh-Token": refresh_token}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
