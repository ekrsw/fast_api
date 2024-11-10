import pytest
import uuid
import asyncio
from datetime import datetime, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import models, schemas, crud
from app.auth import pwd_context


@pytest.fixture
def unique_username():
    """ユニークなユーザー名を生成するフィクスチャ"""
    return f"user_{uuid.uuid4()}"


@pytest.fixture
def unique_item_name():
    """ユニークなアイテム名を生成するフィクスチャ"""
    return f"item_{uuid.uuid4()}"


@pytest.mark.asyncio
async def test_create_user_model(db_session: AsyncSession, unique_username: str):
    """
    Userモデルを作成し、フィールドが正しく設定されていることを確認します。
    """
    password = "securepassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    assert user.id is not None, "ユーザーIDが設定されていること"
    assert user.username == unique_username, "ユーザー名が正しいこと"
    assert user.is_admin is False, "is_adminがFalseであること"
    assert pwd_context.verify(password, user.hashed_password), "パスワードが正しくハッシュ化されていること"
    assert user.created_at is not None, "created_atが設定されていること"
    assert user.updated_at is not None, "updated_atが設定されていること"
    assert isinstance(user.created_at, datetime), "created_atがdatetime型であること"
    assert isinstance(user.updated_at, datetime), "updated_atがdatetime型であること"


@pytest.mark.asyncio
async def test_create_item_model(db_session: AsyncSession, unique_item_name: str):
    """
    Itemモデルを作成し、フィールドが正しく設定されていることを確認します。
    """
    item_create = schemas.ItemCreate(name=unique_item_name)
    item = await crud.create_item(db_session, item_create)

    assert item.id is not None, "アイテムIDが設定されていること"
    assert item.name == unique_item_name, "アイテム名が正しいこと"
    assert item.created_at is not None, "created_atが設定されていること"
    assert item.updated_at is not None, "updated_atが設定されていること"
    assert isinstance(item.created_at, datetime), "created_atがdatetime型であること"
    assert isinstance(item.updated_at, datetime), "updated_atがdatetime型であること"


@pytest.mark.asyncio
async def test_user_created_at_updated_at(db_session: AsyncSession, unique_username: str):
    """
    Userモデルのcreated_atとupdated_atが正しく設定されていることを確認します。
    """
    user_create = schemas.UserCreate(username=unique_username, password="password")
    user = await crud.create_user(db_session, user_create)

    assert user.created_at <= datetime.utcnow(), "created_atが現在時刻以前であること"
    assert user.updated_at <= datetime.utcnow(), "updated_atが現在時刻以前であること"

    # 少し待ってからユーザーを更新
    await asyncio.sleep(1)  # 時間差を確保
    user_update = schemas.UserUpdate(username="newusername")
    updated_user = await crud.update_user(db_session, username=unique_username, user_update=user_update)

    assert updated_user.updated_at > updated_user.created_at, "updated_atがcreated_atより新しいこと"


@pytest.mark.asyncio
async def test_item_created_at_updated_at(db_session: AsyncSession, unique_item_name: str):
    """
    Itemモデルのcreated_atとupdated_atが正しく設定されていることを確認します。
    """
    item_create = schemas.ItemCreate(name=unique_item_name)
    item = await crud.create_item(db_session, item_create)

    assert item.created_at <= datetime.utcnow(), "created_atが現在時刻以前であること"
    assert item.updated_at <= datetime.utcnow(), "updated_atが現在時刻以前であること"

    # 少し待ってからアイテムを更新
    await asyncio.sleep(1)  # 時間差を確保
    item_update = schemas.ItemCreate(name="updatedname")
    updated_item = await crud.update_item(db_session, item_id=item.id, item=item_update)

    assert updated_item.updated_at > updated_item.created_at, "updated_atがcreated_atより新しいこと"
    assert updated_item.name == "updatedname", "アイテム名が更新されていること"


@pytest.mark.asyncio
async def test_user_model_constraints(db_session: AsyncSession, unique_username: str):
    """
    Userモデルのユニーク制約をテストします。重複するユーザー名での作成が失敗することを確認します。
    """
    user_create = schemas.UserCreate(username=unique_username, password="password")
    await crud.create_user(db_session, user_create)

    with pytest.raises(Exception) as exc_info:
        # 同じユーザー名で再度ユーザーを作成
        await crud.create_user(db_session, user_create)
    
    # エラーメッセージや例外の種類を確認することもできます
    # 例えば、SQLAlchemyのIntegrityErrorを期待する場合：
    # from sqlalchemy.exc import IntegrityError
    # assert isinstance(exc_info.value, IntegrityError)
    assert exc_info.type is not None, "重複ユーザー名での作成時に例外が発生すること"


@pytest.mark.asyncio
async def test_item_model_constraints(db_session: AsyncSession, unique_item_name: str):
    """
    Itemモデルのユニーク制約（もしあれば）をテストします。重複するアイテム名での作成が失敗することを確認します。
    """
    # 既にunique制約がある場合のみテストします。現状models.pyではnameにunique制約がないので、このテストは不要かもしれません。
    # ここではnameがuniqueではないため、同じ名前で複数のアイテムを作成できることを確認します。
    item_create = schemas.ItemCreate(name=unique_item_name)
    item1 = await crud.create_item(db_session, item_create)
    item2 = await crud.create_item(db_session, item_create)

    assert item1.id != item2.id, "異なるIDを持つアイテムが作成されること"
    assert item1.name == item2.name, "同じ名前のアイテムが作成されること"
