import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt
from app import schemas, crud
from app.config import settings

import uuid

@pytest.fixture
def unique_username():
    """ユニークなユーザー名を生成するフィクスチャ"""
    return f"user_{uuid.uuid4()}"


@pytest.mark.asyncio
async def test_login_for_access_token_success(client: AsyncClient, db_session: AsyncSession):
    """
    正しい認証情報を使用してアクセストークンとリフレッシュトークンを取得できることを確認します。
    """
    # テストユーザーの作成
    username = "testuser"
    password = "testpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    # /auth/token エンドポイントにリクエストを送信
    response = await client.post(
        "/auth/token",
        data={"username": username, "password": password}
    )

    assert response.status_code == 200, f"トークン取得に失敗しました: {response.text}"
    tokens = response.json()
    assert "access_token" in tokens, "レスポンスに access_token が含まれていません"
    assert tokens["token_type"] == "bearer", "トークンタイプが正しくありません"
    assert "refresh_token" in tokens, "レスポンスに refresh_token が含まれていません"

    # アクセストークンのデコードと検証
    access_token = tokens["access_token"]
    payload = jwt.decode(access_token, settings.secret_key, algorithms=[settings.algorithm])
    assert payload.get("sub") == username, "アクセストークンのペイロードが正しくありません"


@pytest.mark.asyncio
async def test_login_for_access_token_invalid_credentials(client: AsyncClient):
    """
    無効な認証情報でトークン取得が失敗することを確認します。
    """
    # 存在しないユーザーでリクエストを送信
    response = await client.post(
        "/auth/token",
        data={"username": "invaliduser", "password": "invalidpassword"}
    )

    assert response.status_code == 401, "無効な認証情報で 401 エラーが返されるべきです"
    assert response.json()["detail"] == "Incorrect username or password", "エラーメッセージが正しくありません"


@pytest.mark.asyncio
async def test_refresh_access_token_success(client: AsyncClient, db_session: AsyncSession, unique_username):
    """
    正しいリフレッシュトークンを使用して新しいアクセストークンを取得できることを確認します。
    """
    # テストユーザーの作成
    username = unique_username
    password = "testpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    # トークン取得
    response = await client.post(
        "/auth/token",
        data={"username": username, "password": password}
    )
    tokens = response.json()
    refresh_token = tokens["refresh_token"]

    # /auth/refresh エンドポイントにリクエストを送信
    response = await client.post(
        "/auth/refresh",
        headers={"Refresh-Token": refresh_token}
    )

    assert response.status_code == 200, f"アクセストークンのリフレッシュに失敗しました: {response.text}"
    new_tokens = response.json()
    assert "access_token" in new_tokens, "レスポンスに新しい access_token が含まれていません"
    assert new_tokens["token_type"] == "bearer", "トークンタイプが正しくありません"

    # 新しいアクセストークンのデコードと検証
    access_token = new_tokens["access_token"]
    payload = jwt.decode(access_token, settings.secret_key, algorithms=[settings.algorithm])
    assert payload.get("sub") == username, "新しいアクセストークンのペイロードが正しくありません"


@pytest.mark.asyncio
async def test_refresh_access_token_invalid_token(client: AsyncClient):
    """
    無効なリフレッシュトークンでアクセストークンのリフレッシュが失敗することを確認します。
    """
    # 無効なリフレッシュトークンを使用
    response = await client.post(
        "/auth/refresh",
        headers={"Refresh-Token": "invalidtoken"}
    )

    assert response.status_code == 401, "無効なリフレッシュトークンで 401 エラーが返されるべきです"
    assert response.json()["detail"] == "Invalid token", "エラーメッセージが正しくありません"


@pytest.mark.asyncio
async def test_access_protected_route_with_token(client: AsyncClient, db_session: AsyncSession):
    """
    取得したアクセストークンを使用して保護されたエンドポイントにアクセスできることを確認します。
    """
    # テストユーザーの作成
    username = "protecteduser"
    password = "protectedpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    # トークン取得
    response = await client.post(
        "/auth/token",
        data={"username": username, "password": password}
    )
    tokens = response.json()
    access_token = tokens["access_token"]

    # 保護されたエンドポイントにアクセス
    response = await client.get(
        f"/users/{username}",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 200, f"保護されたエンドポイントへのアクセスに失敗しました: {response.text}"
    data = response.json()
    assert data["username"] == username, "取得したユーザー名が正しくありません"


@pytest.mark.asyncio
async def test_access_protected_route_with_invalid_token(client: AsyncClient):
    """
    無効なアクセストークンで保護されたエンドポイントにアクセスできないことを確認します。
    """
    # 無効なアクセストークンを使用
    response = await client.get(
        "/users/someuser",
        headers={"Authorization": "Bearer invalidtoken"}
    )

    assert response.status_code == 401, "無効なアクセストークンで 401 エラーが返されるべきです"
    assert response.json()["detail"] == "Could not validate credentials", "エラーメッセージが正しくありません"
