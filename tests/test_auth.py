import pytest
import uuid
from datetime import timedelta, datetime
from jose import JWTError
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from app import auth, schemas, crud
from app.config import settings
from app.models import User

# パスワードコンテキストを再利用
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@pytest.fixture
def unique_username():
    """ユニークなユーザー名を生成するフィクスチャ"""
    return f"user_{uuid.uuid4()}"


@pytest.mark.asyncio
async def test_verify_password():
    password = "testpassword"
    hashed_password = pwd_context.hash(password)
    assert auth.verify_password(password, hashed_password) is True
    assert auth.verify_password("wrongpassword", hashed_password) is False


@pytest.mark.asyncio
async def test_get_password_hash():
    password = "testpassword"
    hashed_password = auth.get_password_hash(password)
    assert pwd_context.verify(password, hashed_password) is True


@pytest.mark.asyncio
async def test_create_jwt_token_default_expiry():
    data = {"sub": "testuser"}
    token = auth.create_jwt_token(
        data=data,
        secret_key="testsecret",
        algorithm="HS256"
    )
    assert isinstance(token, str)

    # デコードして有効期限を確認
    decoded = auth.decode_token(token, "testsecret", ["HS256"])
    assert decoded["sub"] == "testuser"
    assert "exp" in decoded

    # 有効期限が約15分後であることを確認
    exp = datetime.utcfromtimestamp(decoded["exp"])
    now = datetime.utcnow()
    delta = exp - now
    assert timedelta(minutes=14) < delta < timedelta(minutes=16)


@pytest.mark.asyncio
async def test_create_jwt_token_custom_expiry():
    data = {"sub": "testuser"}
    custom_expiry = timedelta(minutes=30)
    token = auth.create_jwt_token(
        data=data,
        secret_key="testsecret",
        algorithm="HS256",
        expires_delta=custom_expiry
    )
    decoded = auth.decode_token(token, "testsecret", ["HS256"])
    exp = datetime.utcfromtimestamp(decoded["exp"])
    now = datetime.utcnow()
    delta = exp - now
    assert timedelta(minutes=29) < delta < timedelta(minutes=31)


@pytest.mark.asyncio
async def test_create_access_token():
    data = {"sub": "testuser"}
    token = auth.create_access_token(data=data)
    assert isinstance(token, str)
    decoded = auth.decode_token(token, settings.secret_key, [settings.algorithm])
    assert decoded["sub"] == "testuser"


@pytest.mark.asyncio
async def test_create_refresh_token_default_expiry():
    data = {"sub": "testuser"}
    token = auth.create_refresh_token(data=data)
    assert isinstance(token, str)
    decoded = auth.decode_token(token, settings.refresh_secret_key, [settings.refresh_algorithm])
    assert decoded["sub"] == "testuser"
    # 有効期限が約1日後であることを確認
    exp = datetime.utcfromtimestamp(decoded["exp"])
    now = datetime.utcnow()
    delta = exp - now
    assert timedelta(days=0, hours=23) < delta < timedelta(days=1, hours=1)


@pytest.mark.asyncio
async def test_create_refresh_token_custom_expiry():
    data = {"sub": "testuser"}
    custom_expiry = timedelta(days=2)
    token = auth.create_refresh_token(data=data, expires_delta=custom_expiry)
    decoded = auth.decode_token(token, settings.refresh_secret_key, [settings.refresh_algorithm])
    exp = datetime.utcfromtimestamp(decoded["exp"])
    now = datetime.utcnow()
    delta = exp - now
    assert timedelta(days=1, hours=23) < delta < timedelta(days=2, hours=1)


@pytest.mark.asyncio
async def test_decode_token_invalid_secret():
    data = {"sub": "testuser"}
    token = auth.create_jwt_token(data=data, secret_key="testsecret", algorithm="HS256")
    with pytest.raises(JWTError):
        auth.decode_token(token, "wrongsecret", ["HS256"])


@pytest.mark.asyncio
async def test_authenticate_user_success(db_session, unique_username):
    username = unique_username
    password = "testpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    user = await auth.authenticate_user(db_session, username, password)
    assert user is not None
    assert user.username == username


@pytest.mark.asyncio
async def test_authenticate_user_wrong_password(db_session, unique_username):
    username = unique_username
    password = "testpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    user = await auth.authenticate_user(db_session, username, "wrongpassword")
    assert user is None


@pytest.mark.asyncio
async def test_authenticate_user_nonexistent_user(db_session):
    user = await auth.authenticate_user(db_session, "nonexistentuser", "password")
    assert user is None


@pytest.mark.asyncio
async def test_get_current_user_success(client, db_session, unique_username):
    username = unique_username
    password = "currentpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    # トークン取得
    response = await client.post(
        "/auth/token",
        data={"username": username, "password": password}
    )
    assert response.status_code == 200
    tokens = response.json()
    access_token = tokens["access_token"]

    # ユーザー取得
    response = await client.get(
        f"/users/{username}",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == username


@pytest.mark.asyncio
async def test_get_current_user_invalid_token(client):
    # 無効なトークンを使用
    invalid_token = "invalidtoken123"

    response = await client.get(
        "/users/testuser",
        headers={"Authorization": f"Bearer {invalid_token}"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


@pytest.mark.asyncio
async def test_get_refresh_token_header_present(client, db_session, unique_username):
    # テストユーザーの作成
    username = unique_username
    password = "refreshpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    # トークン取得
    response = await client.post(
        "/auth/token",
        data={"username": username, "password": password}
    )
    assert response.status_code == 200
    tokens = response.json()
    refresh_token = tokens.get("refresh_token")
    assert refresh_token is not None

    # リフレッシュトークンを使用して新しいアクセストークンを取得
    response = await client.post(
        "/auth/refresh",
        headers={"Refresh-Token": refresh_token}
    )
    print("Response Status Code:", response.status_code)
    print("Response JSON:", response.json())  # エラー内容を出力
    assert response.status_code == 200
    new_tokens = response.json()
    assert "access_token" in new_tokens
    assert new_tokens["token_type"] == "bearer"

