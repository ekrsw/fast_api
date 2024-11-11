import pytest
import uuid
from httpx import AsyncClient

from sqlalchemy.ext.asyncio import AsyncSession

from app import schemas, crud
from app.auth import create_access_token
from app.config import settings
from datetime import timedelta


@pytest.fixture
def unique_item_name():
    """テスト用のユニークなアイテム名を生成します。"""
    return f"item_{uuid.uuid4()}"


@pytest.fixture
def unique_username():
    """テスト用のユニークなユーザー名を生成します。"""
    return f"user_{uuid.uuid4()}"


@pytest.mark.asyncio
async def test_create_item(client: AsyncClient, db_session: AsyncSession, unique_item_name: str, unique_username: str):
    """
    新しいアイテムを作成するテスト。

    有効なアクセストークンが提供された場合に新しいアイテムが作成できることを確認します。
    """
    # テストユーザーを作成
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # アクセストークンを生成
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # 認証ヘッダーを準備
    headers = {"Authorization": f"Bearer {access_token}"}

    # アイテムデータ
    item_data = {"name": unique_item_name}

    # アイテム作成リクエストを送信
    response = await client.post("/items/", json=item_data, headers=headers)

    assert response.status_code == 200, f"アイテムの作成に失敗しました: {response.text}"
    item = response.json()
    assert item["name"] == unique_item_name, "アイテム名が一致しません"
    assert "id" in item, "アイテムIDが返されていません"
    assert "created_at" in item, "アイテムの作成日時が返されていません"
    assert "updated_at" in item, "アイテムの更新日時が返されていません"


@pytest.mark.asyncio
async def test_read_items(client: AsyncClient, db_session: AsyncSession, unique_item_name: str, unique_username: str):
    """
    複数のアイテムを取得するテスト。

    有効なアクセストークンが提供された場合に複数のアイテムが取得できることを確認します。
    """
    # テストユーザーを作成
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # アクセストークンを生成
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # 認証ヘッダーを準備
    headers = {"Authorization": f"Bearer {access_token}"}

    # 複数のアイテムを作成
    item_names = [f"item_{uuid.uuid4()}" for _ in range(5)]
    for name in item_names:
        item_data = {"name": name}
        await client.post("/items/", json=item_data, headers=headers)

    # アイテム取得リクエストを送信
    response = await client.get("/items/", headers=headers)

    assert response.status_code == 200, f"アイテムの取得に失敗しました: {response.text}"
    items = response.json()
    retrieved_names = [item["name"] for item in items]
    for name in item_names:
        assert name in retrieved_names, f"アイテム {name} が取得結果に含まれていません"


@pytest.mark.asyncio
async def test_read_item(client: AsyncClient, db_session: AsyncSession, unique_item_name: str, unique_username: str):
    """
    特定のアイテムを取得するテスト。

    有効なアクセストークンが提供された場合に特定のアイテムがIDで取得できることを確認します。
    """
    # テストユーザーを作成
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # アクセストークンを生成
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # 認証ヘッダーを準備
    headers = {"Authorization": f"Bearer {access_token}"}

    # アイテムを作成
    item_data = {"name": unique_item_name}
    create_response = await client.post("/items/", json=item_data, headers=headers)
    item = create_response.json()
    item_id = item["id"]

    # 特定のアイテム取得リクエストを送信
    response = await client.get(f"/items/{item_id}", headers=headers)

    assert response.status_code == 200, f"アイテムの取得に失敗しました: {response.text}"
    retrieved_item = response.json()
    assert retrieved_item["id"] == item_id, "アイテムIDが一致しません"
    assert retrieved_item["name"] == unique_item_name, "アイテム名が一致しません"


@pytest.mark.asyncio
async def test_update_item(client: AsyncClient, db_session: AsyncSession, unique_item_name: str, unique_username: str):
    """
    アイテムを更新するテスト。

    有効なアクセストークンが提供された場合にアイテムが更新できることを確認します。
    """
    # テストユーザーを作成
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # アクセストークンを生成
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # 認証ヘッダーを準備
    headers = {"Authorization": f"Bearer {access_token}"}

    # アイテムを作成
    item_data = {"name": unique_item_name}
    create_response = await client.post("/items/", json=item_data, headers=headers)
    item = create_response.json()
    item_id = item["id"]

    # 更新データ
    updated_name = "Updated Item Name"
    update_data = {"name": updated_name}

    # アイテム更新リクエストを送信
    response = await client.put(f"/items/{item_id}", json=update_data, headers=headers)

    assert response.status_code == 200, f"アイテムの更新に失敗しました: {response.text}"
    updated_item = response.json()
    assert updated_item["id"] == item_id, "アイテムIDが一致しません"
    assert updated_item["name"] == updated_name, "アイテム名が更新されていません"


@pytest.mark.asyncio
async def test_delete_item(client: AsyncClient, db_session: AsyncSession, unique_item_name: str, unique_username: str):
    """
    アイテムを削除するテスト。

    有効なアクセストークンが提供された場合にアイテムが削除できることを確認します。
    """
    # テストユーザーを作成
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # アクセストークンを生成
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # 認証ヘッダーを準備
    headers = {"Authorization": f"Bearer {access_token}"}

    # アイテムを作成
    item_data = {"name": unique_item_name}
    create_response = await client.post("/items/", json=item_data, headers=headers)
    item = create_response.json()
    item_id = item["id"]

    # アイテム削除リクエストを送信
    response = await client.delete(f"/items/{item_id}", headers=headers)

    assert response.status_code == 200, f"アイテムの削除に失敗しました: {response.text}"
    detail = response.json()
    assert detail["detail"] == "Item deleted", "削除メッセージが一致しません"

    # アイテムが存在しないことを確認
    get_response = await client.get(f"/items/{item_id}", headers=headers)
    assert get_response.status_code == 404, "削除されたアイテムが取得できてはいけません"


@pytest.mark.asyncio
async def test_unauthorized_access(client: AsyncClient):
    """
    アイテムエンドポイントへの未認証アクセスのテスト。

    有効なトークンなしでアクセスした場合に401エラーが返されることを確認します。
    """
    # トークンなしでアイテムエンドポイントにアクセス
    response = await client.get("/items/")
    assert response.status_code == 401, "未認証アクセスは401を返すべきです"
    assert response.json()["detail"] == "Not authenticated", "エラーメッセージが一致しません"


@pytest.mark.asyncio
async def test_update_nonexistent_item(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    存在しないアイテムを更新するテスト。

    存在しないアイテムを更新しようとした場合に404エラーが返されることを確認します。
    """
    # テストユーザーを作成
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # アクセストークンを生成
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # 認証ヘッダーを準備
    headers = {"Authorization": f"Bearer {access_token}"}

    # 更新データ
    updated_name = "Updated Item Name"
    update_data = {"name": updated_name}

    # 存在しないアイテムIDを使用
    non_existent_item_id = 9999

    # アイテム更新リクエストを送信
    response = await client.put(f"/items/{non_existent_item_id}", json=update_data, headers=headers)

    assert response.status_code == 404, "存在しないアイテムの更新は404を返すべきです"
    assert response.json()["detail"] == "Item not found", "エラーメッセージが一致しません"


@pytest.mark.asyncio
async def test_delete_nonexistent_item(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    存在しないアイテムを削除するテスト。

    存在しないアイテムを削除しようとした場合に404エラーが返されることを確認します。
    """
    # テストユーザーを作成
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # アクセストークンを生成
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # 認証ヘッダーを準備
    headers = {"Authorization": f"Bearer {access_token}"}

    # 存在しないアイテムIDを使用
    non_existent_item_id = 9999

    # アイテム削除リクエストを送信
    response = await client.delete(f"/items/{non_existent_item_id}", headers=headers)

    assert response.status_code == 404, "存在しないアイテムの削除は404を返すべきです"
    assert response.json()["detail"] == "Item not found", "エラーメッセージが一致しません"

