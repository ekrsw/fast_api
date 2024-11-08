import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app import crud, schemas

@pytest.mark.asyncio
async def test_register_user(client: AsyncClient, db_session: AsyncSession):
    """
    新規ユーザー登録エンドポイントのテスト。
    """
    # 初期管理者ユーザーの作成
    admin_create = schemas.UserCreate(
        username="test_admin",
        password="test_admin_password"
    )
    await crud.create_user(db=db_session, user=admin_create, is_admin=True)
    
    # ログインしてアクセストークンを取得
    login_response = await client.post(
        "/auth/token",
        data={"username": admin_create.username, "password": admin_create.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert login_response.status_code == 200
    tokens = login_response.json()
    access_token = tokens["access_token"]
    
    # 新規ユーザー登録リクエストの送信
    headers = {"Authorization": f"Bearer {access_token}"}
    user_data = {"username": "new_user", "password": "new_password"}
    response = await client.post("/users/", json=user_data, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "new_user"
    assert not data["is_admin"]

@pytest.mark.asyncio
async def test_read_user(client: AsyncClient, db_session: AsyncSession):
    """
    特定のユーザー取得エンドポイントのテスト。
    """
    # 初期管理者ユーザーの作成
    admin_create = schemas.UserCreate(
        username="test_admin",
        password="test_admin_password"
    )
    await crud.create_user(db=db_session, user=admin_create, is_admin=True)
    
    # 新規ユーザーの作成
    user_create = schemas.UserCreate(
        username="read_user",
        password="read_password"
    )
    await crud.create_user(db=db_session, user=user_create, is_admin=False)
    
    # ログインしてアクセストークンを取得
    login_response = await client.post(
        "/auth/token",
        data={"username": admin_create.username, "password": admin_create.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    tokens = login_response.json()
    access_token = tokens["access_token"]
    
    # 特定のユーザー取得リクエストの送信
    headers = {"Authorization": f"Bearer {access_token}"}
    response = await client.get("/users/read_user", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "read_user"
    assert not data["is_admin"]

@pytest.mark.asyncio
async def test_read_users(client: AsyncClient, db_session: AsyncSession):
    """
    ユーザー一覧取得エンドポイントのテスト。
    """
    # 初期管理者ユーザーの作成
    admin_create = schemas.UserCreate(
        username="test_admin",
        password="test_admin_password"
    )
    await crud.create_user(db=db_session, user=admin_create, is_admin=True)
    
    # 複数のユーザーの作成
    for i in range(5):
        user_data = schemas.UserCreate(username=f"user_{i}", password=f"password_{i}")
        await crud.create_user(db=db_session, user=user_data, is_admin=False)
    
    # ログインしてアクセストークンを取得
    login_response = await client.post(
        "/auth/token",
        data={"username": admin_create.username, "password": admin_create.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    tokens = login_response.json()
    access_token = tokens["access_token"]
    
    # ユーザー一覧取得リクエストの送信
    headers = {"Authorization": f"Bearer {access_token}"}
    response = await client.get("/users/", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 5

@pytest.mark.asyncio
async def test_update_user_info(client: AsyncClient, db_session: AsyncSession):
    """
    ユーザー情報更新エンドポイントのテスト。
    """
    # 初期管理者ユーザーの作成
    admin_create = schemas.UserCreate(
        username="test_admin",
        password="test_admin_password"
    )
    await crud.create_user(db=db_session, user=admin_create, is_admin=True)
    
    # 新規ユーザーの作成
    user_create = schemas.UserCreate(
        username="update_user",
        password="update_password"
    )
    await crud.create_user(db=db_session, user=user_create, is_admin=False)
    
    # ログインしてアクセストークンを取得
    login_response = await client.post(
        "/auth/token",
        data={"username": admin_create.username, "password": admin_create.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    tokens = login_response.json()
    access_token = tokens["access_token"]
    
    # ユーザー情報更新リクエストの送信
    headers = {"Authorization": f"Bearer {access_token}"}
    update_data = {"password": "new_password"}
    response = await client.put("/users/update_user", json=update_data, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "update_user"
    
    # パスワードが更新されたことを確認
    user_in_db = await crud.get_user_by_username(db=db_session, username="update_user")
    assert crud.verify_password("new_password", user_in_db.hashed_password)

@pytest.mark.asyncio
async def test_delete_user(client: AsyncClient, db_session: AsyncSession):
    """
    ユーザー削除エンドポイントのテスト。
    """
    # 初期管理者ユーザーの作成
    admin_create = schemas.UserCreate(
        username="test_admin",
        password="test_admin_password"
    )
    await crud.create_user(db=db_session, user=admin_create, is_admin=True)
    
    # 新規ユーザーの作成
    user_create = schemas.UserCreate(
        username="delete_user",
        password="delete_password"
    )
    await crud.create_user(db=db_session, user=user_create, is_admin=False)
    
    # ログインしてアクセストークンを取得
    login_response = await client.post(
        "/auth/token",
        data={"username": admin_create.username, "password": admin_create.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    tokens = login_response.json()
    access_token = tokens["access_token"]
    
    # ユーザー削除リクエストの送信
    headers = {"Authorization": f"Bearer {access_token}"}
    response = await client.delete("/users/delete_user", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["detail"] == "User 'delete_user' deleted"
    
    # 削除後にユーザーが存在しないことを確認
    response = await client.get("/users/delete_user", headers=headers)
    assert response.status_code == 404
    data = response.json()
    assert data["detail"] == "User not found"
