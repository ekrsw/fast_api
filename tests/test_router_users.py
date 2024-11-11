# tests/test_router_users.py
import pytest
import uuid
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app import crud, schemas
from app.main import app
from app.dependencies import get_db
from app.auth import get_password_hash
from tests.conftest import override_get_db


@pytest.fixture
def unique_username():
    """ユニークなユーザー名を生成するフィクスチャ"""
    return f"user_{uuid.uuid4()}"


@pytest.fixture
def unique_admin_username():
    """ユニークな管理者ユーザー名を生成するフィクスチャ"""
    return f"admin_{uuid.uuid4()}"


@pytest.mark.asyncio
async def test_register_user(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    新しいユーザーを登録するテスト。
    他のテスト（test_auth.py）でのユーザー作成方法を参考にしています。
    """
    # ユーザー登録データ
    user_data = {"username": unique_username, "password": "testpassword"}

    # ユーザー登録APIを呼び出す
    response = await client.post("/users/", json=user_data)
    assert response.status_code == 200, f"ユーザー登録に失敗しました: {response.text}"

    # レスポンスデータを検証
    data = response.json()
    assert data["username"] == unique_username
    assert "id" in data
    assert "is_admin" in data
    assert data["is_admin"] is False


@pytest.mark.asyncio
async def test_register_user_existing_username(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    既存のユーザー名でユーザー登録を試み、エラーを確認するテスト。
    """
    # 既存ユーザーを作成
    user_create = schemas.UserCreate(username=unique_username, password="password1")
    await crud.create_user(db_session, user_create)

    # 同じユーザー名で登録を試みる
    user_data = {"username": unique_username, "password": "password2"}
    response = await client.post("/users/", json=user_data)
    assert response.status_code == 400, "既存のユーザー名で登録が成功してはいけません"
    assert response.json()["detail"] == "Username already registered"


@pytest.mark.asyncio
async def test_read_user(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    特定のユーザーを取得するテスト。
    認証が必要なため、トークン取得方法は test_auth.py を参考にしています。
    """
    # テストユーザーを作成
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    await crud.create_user(db_session, user_create)

    # トークンを取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_username, "password": password}
    )
    tokens = response.json()
    access_token = tokens["access_token"]

    # ユーザー情報を取得
    response = await client.get(
        f"/users/{unique_username}",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200, f"ユーザー取得に失敗しました: {response.text}"
    data = response.json()
    assert data["username"] == unique_username


@pytest.mark.asyncio
async def test_read_users(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    複数のユーザーを取得するテスト。
    """
    # テストユーザーを複数作成
    usernames = [unique_username] + [f"user_{uuid.uuid4()}" for _ in range(2)]
    for uname in usernames:
        user_create = schemas.UserCreate(username=uname, password="password")
        await crud.create_user(db_session, user_create)

    # 認証ユーザーでトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": usernames[0], "password": "password"}
    )
    tokens = response.json()
    access_token = tokens["access_token"]

    # ユーザー一覧を取得
    response = await client.get(
        "/users/",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200, f"ユーザー一覧取得に失敗しました: {response.text}"
    data = response.json()
    retrieved_usernames = [user["username"] for user in data]
    for uname in usernames:
        assert uname in retrieved_usernames


@pytest.mark.asyncio
async def test_add_user_as_admin(client: AsyncClient, db_session: AsyncSession, unique_admin_username: str, unique_username: str):
    """
    管理者ユーザーが新しいユーザーを追加するテスト。
    """
    # 管理者ユーザーを作成
    admin_password = "adminpassword"
    admin_user = await crud.create_user(
        db_session,
        schemas.UserCreate(username=unique_admin_username, password=admin_password),
        is_admin=True
    )

    # 管理者でトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_admin_username, "password": admin_password}
    )
    tokens = response.json()
    admin_access_token = tokens["access_token"]

    # 新規ユーザーを追加
    user_data = {"username": unique_username, "password": "newpassword"}
    response = await client.post(
        "/users/add",
        json=user_data,
        headers={"Authorization": f"Bearer {admin_access_token}"}
    )
    assert response.status_code == 200, f"ユーザー追加に失敗しました: {response.text}"
    data = response.json()
    assert data["username"] == unique_username


@pytest.mark.asyncio
async def test_add_user_as_non_admin(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    一般ユーザーが新しいユーザーを追加しようとして失敗するテスト。
    """
    # 一般ユーザーを作成
    user_password = "userpassword"
    user_create = schemas.UserCreate(username=unique_username, password=user_password)
    await crud.create_user(db_session, user_create)

    # 一般ユーザーでトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_username, "password": user_password}
    )
    tokens = response.json()
    user_access_token = tokens["access_token"]

    # 新規ユーザーを追加しようとする
    new_user_data = {"username": "unauthorized_user", "password": "password"}
    response = await client.post(
        "/users/add",
        json=new_user_data,
        headers={"Authorization": f"Bearer {user_access_token}"}
    )
    assert response.status_code == 403, "一般ユーザーがユーザー追加できてはいけません"
    assert response.json()["detail"] == "Not authorized to add users"


@pytest.mark.asyncio
async def test_update_user_info(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    ユーザーが自身の情報を更新するテスト。
    """
    # ユーザーを作成
    user_password = "oldpassword"
    user_create = schemas.UserCreate(username=unique_username, password=user_password)
    await crud.create_user(db_session, user_create)

    # トークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_username, "password": user_password}
    )
    tokens = response.json()
    access_token = tokens["access_token"]

    # ユーザー情報を更新
    update_data = {"username": unique_username, "password": "newpassword"}
    response = await client.put(
        f"/users/{unique_username}",
        json=update_data,
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200, f"ユーザー情報更新に失敗しました: {response.text}"
    data = response.json()
    assert data["username"] == unique_username

    # 新しいパスワードでログインできることを確認
    response = await client.post(
        "/auth/token",
        data={"username": unique_username, "password": "newpassword"}
    )
    assert response.status_code == 200, "新しいパスワードでログインできません"


@pytest.mark.asyncio
async def test_update_other_user_info_as_admin(client: AsyncClient, db_session: AsyncSession, unique_admin_username: str, unique_username: str):
    """
    管理者が他のユーザーの情報を更新するテスト。
    """
    # 管理者ユーザーを作成
    admin_password = "adminpassword"
    await crud.create_user(
        db_session,
        schemas.UserCreate(username=unique_admin_username, password=admin_password),
        is_admin=True
    )

    # 一般ユーザーを作成
    user_password = "userpassword"
    await crud.create_user(
        db_session,
        schemas.UserCreate(username=unique_username, password=user_password)
    )

    # 管理者でトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_admin_username, "password": admin_password}
    )
    tokens = response.json()
    admin_access_token = tokens["access_token"]

    # 一般ユーザーの情報を更新
    update_data = {"is_admin": True}
    response = await client.put(
        f"/users/{unique_username}",
        json=update_data,
        headers={"Authorization": f"Bearer {admin_access_token}"}
    )
    assert response.status_code == 200, f"ユーザー情報更新に失敗しました: {response.text}"
    data = response.json()
    assert data["is_admin"] is True


@pytest.mark.asyncio
async def test_update_other_user_info_as_non_admin(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    一般ユーザーが他のユーザーの情報を更新しようとして失敗するテスト。
    """
    # ユーザーを2人作成
    user1_password = "password1"
    user2_password = "password2"
    user1 = schemas.UserCreate(username=unique_username, password=user1_password)
    user2 = schemas.UserCreate(username=f"user_{uuid.uuid4()}", password=user2_password)
    await crud.create_user(db_session, user1)
    await crud.create_user(db_session, user2)

    # ユーザー1でトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_username, "password": user1_password}
    )
    tokens = response.json()
    user1_access_token = tokens["access_token"]

    # ユーザー2の情報を更新しようとする
    update_data = {"password": "hackedpassword"}
    response = await client.put(
        f"/users/{user2.username}",
        json=update_data,
        headers={"Authorization": f"Bearer {user1_access_token}"}
    )
    assert response.status_code == 403, "他のユーザーの情報を更新できてはいけません"
    assert response.json()["detail"] == "Not authorized to update this user"


@pytest.mark.asyncio
async def test_delete_user_as_admin(client: AsyncClient, db_session: AsyncSession, unique_admin_username: str, unique_username: str):
    """
    管理者がユーザーを削除するテスト。
    """
    # 管理者ユーザーを作成
    admin_password = "adminpassword"
    await crud.create_user(
        db_session,
        schemas.UserCreate(username=unique_admin_username, password=admin_password),
        is_admin=True
    )

    # 一般ユーザーを作成
    await crud.create_user(
        db_session,
        schemas.UserCreate(username=unique_username, password="userpassword")
    )

    # 管理者でトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_admin_username, "password": admin_password}
    )
    tokens = response.json()
    admin_access_token = tokens["access_token"]

    # ユーザーを削除
    response = await client.delete(
        f"/users/{unique_username}",
        headers={"Authorization": f"Bearer {admin_access_token}"}
    )
    assert response.status_code == 200, f"ユーザー削除に失敗しました: {response.text}"
    assert response.json()["detail"] == f"User '{unique_username}' deleted"

    # ユーザーが削除されたことを確認
    user = await crud.get_user_by_username(db_session, username=unique_username)
    assert user is None, "ユーザーが削除されていません"


@pytest.mark.asyncio
async def test_delete_user_as_non_admin(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    一般ユーザーが他のユーザーを削除しようとして失敗するテスト。
    """
    # ユーザーを2人作成
    user1_password = "password1"
    user2_password = "password2"
    user1 = schemas.UserCreate(username=unique_username, password=user1_password)
    user2_username = f"user_{uuid.uuid4()}"
    user2 = schemas.UserCreate(username=user2_username, password=user2_password)
    await crud.create_user(db_session, user1)
    await crud.create_user(db_session, user2)

    # ユーザー1でトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_username, "password": user1_password}
    )
    tokens = response.json()
    user1_access_token = tokens["access_token"]

    # ユーザー2を削除しようとする
    response = await client.delete(
        f"/users/{user2_username}",
        headers={"Authorization": f"Bearer {user1_access_token}"}
    )
    assert response.status_code == 403, "一般ユーザーが他のユーザーを削除できてはいけません"
    assert response.json()["detail"] == "Not authorized to delete users"
