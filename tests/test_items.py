import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app import crud, schemas

@pytest.mark.asyncio
async def test_create_item(client: AsyncClient, db_session: AsyncSession):
    """
    アイテム作成エンドポイントのテスト。
    """
    # 初期管理者ユーザーの作成
    user_create = schemas.UserCreate(
        username="test_admin",
        password="test_admin_password"
    )
    await crud.create_user(db=db_session, user=user_create, is_admin=True)
    
    # ログインしてアクセストークンを取得
    response = await client.post(
        "/auth/token",
        data={"username": user_create.username, "password": user_create.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    tokens = response.json()
    access_token = tokens["access_token"]
    
    # アイテム作成リクエストの送信
    headers = {"Authorization": f"Bearer {access_token}"}
    item_data = {"name": "Test Item"}
    response = await client.post("/items/", json=item_data, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Test Item"
    assert "id" in data

@pytest.mark.asyncio
async def test_read_items(client: AsyncClient, db_session: AsyncSession):
    """
    アイテム一覧取得エンドポイントのテスト。
    """
    # 初期管理者ユーザーの作成
    user_create = schemas.UserCreate(
        username="test_admin",
        password="test_admin_password"
    )
    await crud.create_user(db=db_session, user=user_create, is_admin=True)
    
    # ログインしてアクセストークンを取得
    response = await client.post(
        "/auth/token",
        data={"username": user_create.username, "password": user_create.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    tokens = response.json()
    access_token = tokens["access_token"]
    
    # アイテムの作成
    headers = {"Authorization": f"Bearer {access_token}"}
    for i in range(5):
        await client.post("/items/", json={"name": f"Item {i}"}, headers=headers)
    
    # アイテム一覧取得リクエストの送信
    response = await client.get("/items/", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 5  # 既存のアイテム数に依存

@pytest.mark.asyncio
async def test_read_item(client: AsyncClient, db_session: AsyncSession):
    """
    特定のアイテム取得エンドポイントのテスト。
    """
    # 初期管理者ユーザーの作成
    user_create = schemas.UserCreate(
        username="test_admin",
        password="test_admin_password"
    )
    await crud.create_user(db=db_session, user=user_create, is_admin=True)
    
    # ログインしてアクセストークンを取得
    response = await client.post(
        "/auth/token",
        data={"username": user_create.username, "password": user_create.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    tokens = response.json()
    access_token = tokens["access_token"]
    
    # アイテムの作成
    headers = {"Authorization": f"Bearer {access_token}"}
    create_response = await client.post("/items/", json={"name": "Unique Item"}, headers=headers)
    item = create_response.json()
    
    # 特定のアイテム取得リクエストの送信
    response = await client.get(f"/items/{item['id']}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Unique Item"

@pytest.mark.asyncio
async def test_update_item(client: AsyncClient, db_session: AsyncSession):
    """
    アイテム更新エンドポイントのテスト。
    """
    # 初期管理者ユーザーの作成
    user_create = schemas.UserCreate(
        username="test_admin",
        password="test_admin_password"
    )
    await crud.create_user(db=db_session, user=user_create, is_admin=True)
    
    # ログインしてアクセストークンを取得
    response = await client.post(
        "/auth/token",
        data={"username": user_create.username, "password": user_create.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    tokens = response.json()
    access_token = tokens["access_token"]
    
    # アイテムの作成
    headers = {"Authorization": f"Bearer {access_token}"}
    create_response = await client.post("/items/", json={"name": "Old Item"}, headers=headers)
    item = create_response.json()
    
    # アイテム更新リクエストの送信
    update_data = {"name": "Updated Item"}
    response = await client.put(f"/items/{item['id']}", json=update_data, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Updated Item"

@pytest.mark.asyncio
async def test_delete_item(client: AsyncClient, db_session: AsyncSession):
    """
    アイテム削除エンドポイントのテスト。
    """
    # 初期管理者ユーザーの作成
    user_create = schemas.UserCreate(
        username="test_admin",
        password="test_admin_password"
    )
    await crud.create_user(db=db_session, user=user_create, is_admin=True)
    
    # ログインしてアクセストークンを取得
    response = await client.post(
        "/auth/token",
        data={"username": user_create.username, "password": user_create.password},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    tokens = response.json()
    access_token = tokens["access_token"]
    
    # アイテムの作成
    headers = {"Authorization": f"Bearer {access_token}"}
    create_response = await client.post("/items/", json={"name": "Item to Delete"}, headers=headers)
    item = create_response.json()
    
    # アイテム削除リクエストの送信
    response = await client.delete(f"/items/{item['id']}", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["detail"] == "Item deleted"
    
    # 削除後にアイテムが存在しないことを確認
    response = await client.get(f"/items/{item['id']}", headers=headers)
    assert response.status_code == 404
    data = response.json()
    assert data["detail"] == "Item not found"
