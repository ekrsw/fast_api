import pytest
import uuid
from typing import List

from sqlalchemy.ext.asyncio import AsyncSession
from app import crud, schemas, models
from app.database import Base


@pytest.fixture
def unique_username():
    """ユニークなユーザー名を生成するフィクスチャ"""
    return f"user_{uuid.uuid4()}"


@pytest.fixture
def unique_item_name():
    """ユニークなアイテム名を生成するフィクスチャ"""
    return f"item_{uuid.uuid4()}"


@pytest.mark.asyncio
async def test_get_user_by_username_existing(db_session: AsyncSession, unique_username: str):
    """
    既存のユーザー名でユーザーを取得できることを確認します。
    """
    # ユーザーを作成
    user_create = schemas.UserCreate(username=unique_username, password="testpassword")
    created_user = await crud.create_user(db_session, user_create)

    # ユーザーを取得
    retrieved_user = await crud.get_user_by_username(db_session, username=unique_username)
    assert retrieved_user is not None
    assert retrieved_user.id == created_user.id
    assert retrieved_user.username == created_user.username
    assert retrieved_user.is_admin == created_user.is_admin


@pytest.mark.asyncio
async def test_get_user_by_username_nonexisting(db_session: AsyncSession):
    """
    存在しないユーザー名でユーザーを取得した場合、Noneが返されることを確認します。
    """
    retrieved_user = await crud.get_user_by_username(db_session, username="nonexistentuser")
    assert retrieved_user is None


@pytest.mark.asyncio
async def test_get_users(db_session: AsyncSession, unique_username: str):
    """
    複数のユーザーを取得できることを確認します。
    """
    # ユーザーを複数作成
    usernames = [f"user_{uuid.uuid4()}" for _ in range(5)]
    for uname in usernames:
        user_create = schemas.UserCreate(username=uname, password="testpassword")
        await crud.create_user(db_session, user_create)

    # ユーザーを取得
    users: List[models.User] = await crud.get_users(db_session, skip=0, limit=10)
    retrieved_usernames = [user.username for user in users]
    for uname in usernames:
        assert uname in retrieved_usernames


@pytest.mark.asyncio
async def test_create_user(db_session: AsyncSession, unique_username: str):
    """
    新しいユーザーを作成できることを確認します。
    """
    user_create = schemas.UserCreate(username=unique_username, password="newpassword")
    created_user = await crud.create_user(db_session, user_create)
    assert created_user is not None
    assert created_user.username == unique_username
    assert created_user.is_admin is False  # デフォルトはFalse
    assert created_user.hashed_password != "newpassword"  # パスワードはハッシュ化されている

    # ハッシュ化されたパスワードを検証
    from app.auth import pwd_context
    assert pwd_context.verify("newpassword", created_user.hashed_password) is True


@pytest.mark.asyncio
async def test_create_user_duplicate(db_session: AsyncSession, unique_username: str):
    """
    既に存在するユーザー名でユーザーを作成しようとした場合、エラーが発生することを確認します。
    """
    user_create = schemas.UserCreate(username=unique_username, password="password1")
    await crud.create_user(db_session, user_create)

    # 同じユーザー名で再度作成を試みる
    with pytest.raises(Exception) as exc_info:
        await crud.create_user(db_session, user_create)
    
    # SQLAlchemyのIntegrityErrorなど、具体的な例外を確認することも可能
    # 例:
    # from sqlalchemy.exc import IntegrityError
    # with pytest.raises(IntegrityError):
    #     await crud.create_user(db_session, user_create)
    assert exc_info.type is not None  # 任意の例外が発生していることを確認


@pytest.mark.asyncio
async def test_update_user_existing(db_session: AsyncSession, unique_username: str):
    """
    既存のユーザー情報を更新できることを確認します。
    """
    # ユーザーを作成
    user_create = schemas.UserCreate(username=unique_username, password="initialpassword")
    created_user = await crud.create_user(db_session, user_create)

    # 更新データ
    user_update = schemas.UserUpdate(
        username="updatedusername",
        password="updatedpassword",
        is_admin=True
    )

    # ユーザーを更新
    updated_user = await crud.update_user(db_session, username=unique_username, user_update=user_update)
    assert updated_user is not None
    assert updated_user.username == "updatedusername"
    assert updated_user.is_admin is True

    # パスワードが更新されていることを確認
    from app.auth import pwd_context
    assert pwd_context.verify("updatedpassword", updated_user.hashed_password) is True


@pytest.mark.asyncio
async def test_update_user_nonexisting(db_session: AsyncSession):
    """
    存在しないユーザーを更新しようとした場合、Noneが返されることを確認します。
    """
    user_update = schemas.UserUpdate(username="newusername", password="newpassword")
    updated_user = await crud.update_user(db_session, username="nonexistentuser", user_update=user_update)
    assert updated_user is None


@pytest.mark.asyncio
async def test_delete_user_existing(db_session: AsyncSession, unique_username: str):
    """
    既存のユーザーを削除できることを確認します。
    """
    # ユーザーを作成
    user_create = schemas.UserCreate(username=unique_username, password="passwordtodelete")
    created_user = await crud.create_user(db_session, user_create)

    # ユーザーを削除
    deleted_user = await crud.delete_user(db_session, username=unique_username)
    assert deleted_user is not None
    assert deleted_user.id == created_user.id
    assert deleted_user.username == created_user.username

    # 削除後にユーザーが存在しないことを確認
    retrieved_user = await crud.get_user_by_username(db_session, username=unique_username)
    assert retrieved_user is None


@pytest.mark.asyncio
async def test_delete_user_nonexisting(db_session: AsyncSession):
    """
    存在しないユーザーを削除しようとした場合、Noneが返されることを確認します。
    """
    deleted_user = await crud.delete_user(db_session, username="nonexistentuser")
    assert deleted_user is None


@pytest.mark.asyncio
async def test_get_item_existing(db_session: AsyncSession, unique_item_name: str):
    """
    既存のアイテムを取得できることを確認します。
    """
    # アイテムを作成
    item_create = schemas.ItemCreate(name=unique_item_name)
    created_item = await crud.create_item(db_session, item_create)

    # アイテムを取得
    retrieved_item = await crud.get_item(db_session, item_id=created_item.id)
    assert retrieved_item is not None
    assert retrieved_item.id == created_item.id
    assert retrieved_item.name == created_item.name


@pytest.mark.asyncio
async def test_get_item_nonexisting(db_session: AsyncSession):
    """
    存在しないアイテムIDでアイテムを取得した場合、Noneが返されることを確認します。
    """
    retrieved_item = await crud.get_item(db_session, item_id=9999)
    assert retrieved_item is None


@pytest.mark.asyncio
async def test_get_items(db_session: AsyncSession, unique_item_name: str):
    """
    複数のアイテムを取得できることを確認します。
    """
    # アイテムを複数作成
    item_names = [f"item_{uuid.uuid4()}" for _ in range(5)]
    for name in item_names:
        item_create = schemas.ItemCreate(name=name)
        await crud.create_item(db_session, item_create)

    # アイテムを取得
    items: List[models.Item] = await crud.get_items(db_session, skip=0, limit=10)
    retrieved_item_names = [item.name for item in items]
    for name in item_names:
        assert name in retrieved_item_names


@pytest.mark.asyncio
async def test_create_item(db_session: AsyncSession, unique_item_name: str):
    """
    新しいアイテムを作成できることを確認します。
    """
    item_create = schemas.ItemCreate(name=unique_item_name)
    created_item = await crud.create_item(db_session, item_create)
    assert created_item is not None
    assert created_item.name == unique_item_name


@pytest.mark.asyncio
async def test_update_item_existing(db_session: AsyncSession, unique_item_name: str):
    """
    既存のアイテムを更新できることを確認します。
    """
    # アイテムを作成
    item_create = schemas.ItemCreate(name=unique_item_name)
    created_item = await crud.create_item(db_session, item_create)

    # 更新データ
    updated_name = "updateditemname"
    item_update = schemas.ItemCreate(name=updated_name)

    # アイテムを更新
    updated_item = await crud.update_item(db_session, item_id=created_item.id, item=item_update)
    assert updated_item is not None
    assert updated_item.id == created_item.id
    assert updated_item.name == updated_name


@pytest.mark.asyncio
async def test_update_item_nonexisting(db_session: AsyncSession):
    """
    存在しないアイテムを更新しようとした場合、Noneが返されることを確認します。
    """
    item_update = schemas.ItemCreate(name="nonexistentitem")
    updated_item = await crud.update_item(db_session, item_id=9999, item=item_update)
    assert updated_item is None


@pytest.mark.asyncio
async def test_delete_item_existing(db_session: AsyncSession, unique_item_name: str):
    """
    既存のアイテムを削除できることを確認します。
    """
    # アイテムを作成
    item_create = schemas.ItemCreate(name=unique_item_name)
    created_item = await crud.create_item(db_session, item_create)

    # アイテムを削除
    deleted_item = await crud.delete_item(db_session, item_id=created_item.id)
    assert deleted_item is not None
    assert deleted_item.id == created_item.id
    assert deleted_item.name == created_item.name

    # 削除後にアイテムが存在しないことを確認
    retrieved_item = await crud.get_item(db_session, item_id=created_item.id)
    assert retrieved_item is None


@pytest.mark.asyncio
async def test_delete_item_nonexisting(db_session: AsyncSession):
    """
    存在しないアイテムを削除しようとした場合、Noneが返されることを確認します。
    """
    deleted_item = await crud.delete_item(db_session, item_id=9999)
    assert deleted_item is None
