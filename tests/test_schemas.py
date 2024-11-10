import pytest
from pydantic import ValidationError
from datetime import datetime

from app import schemas


@pytest.mark.asyncio
async def test_item_base_valid():
    """
    ItemBaseモデルが有効なデータで正常に作成されることを確認します。
    """
    data = {"name": "Test Item"}
    item_base = schemas.ItemBase(**data)
    assert item_base.name == "Test Item"


@pytest.mark.asyncio
async def test_item_base_invalid_missing_name():
    """
    ItemBaseモデルで'name'フィールドが欠けている場合、ValidationErrorが発生することを確認します。
    """
    with pytest.raises(ValidationError) as exc_info:
        schemas.ItemBase()
    assert "name" in str(exc_info.value)


@pytest.mark.asyncio
async def test_item_create_valid():
    """
    ItemCreateモデルが有効なデータで正常に作成されることを確認します。
    """
    data = {"name": "New Item"}
    item_create = schemas.ItemCreate(**data)
    assert item_create.name == "New Item"


@pytest.mark.asyncio
async def test_item_create_invalid_empty_name():
    """
    ItemCreateモデルで'name'が空文字の場合、ValidationErrorが発生することを確認します。
    """
    with pytest.raises(ValidationError) as exc_info:
        schemas.ItemCreate(name="")
    assert "Name must not be empty" in str(exc_info.value)


@pytest.mark.asyncio
async def test_item_valid():
    """
    Itemモデルが有効なデータで正常に作成されることを確認します。
    """
    data = {
        "id": 1,
        "name": "Existing Item",
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }
    item = schemas.Item(**data)
    assert item.id == 1
    assert item.name == "Existing Item"
    assert isinstance(item.created_at, datetime)
    assert isinstance(item.updated_at, datetime)


@pytest.mark.asyncio
async def test_item_invalid_missing_fields():
    """
    Itemモデルで必須フィールドが欠けている場合、ValidationErrorが発生することを確認します。
    """
    with pytest.raises(ValidationError) as exc_info:
        schemas.Item(id=1, name="Item Without Timestamps")
    assert "created_at" in str(exc_info.value)
    assert "updated_at" in str(exc_info.value)


@pytest.mark.asyncio
async def test_user_create_valid():
    """
    UserCreateモデルが有効なデータで正常に作成されることを確認します。
    """
    data = {"username": "testuser", "password": "securepassword"}
    user_create = schemas.UserCreate(**data)
    assert user_create.username == "testuser"
    assert user_create.password == "securepassword"


@pytest.mark.asyncio
async def test_user_create_invalid_short_password():
    """
    UserCreateモデルでパスワードが短すぎる場合、ValidationErrorが発生することを確認します。
    """
    with pytest.raises(ValidationError) as exc_info:
        schemas.UserCreate(username="testuser", password="123")
    assert "Password must be at least 6 characters long" in str(exc_info.value)


@pytest.mark.asyncio
async def test_user_create_invalid_missing_fields():
    """
    UserCreateモデルで必須フィールドが欠けている場合、ValidationErrorが発生することを確認します。
    """
    with pytest.raises(ValidationError) as exc_info:
        schemas.UserCreate(username="testuser")
    assert "password" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        schemas.UserCreate(password="securepassword")
    assert "username" in str(exc_info.value)


@pytest.mark.asyncio
async def test_user_valid():
    """
    Userモデルが有効なデータで正常に作成されることを確認します。
    """
    data = {
        "id": 1,
        "username": "existinguser",
        "is_admin": True
    }
    user = schemas.User(**data)
    assert user.id == 1
    assert user.username == "existinguser"
    assert user.is_admin is True


@pytest.mark.asyncio
async def test_user_invalid_missing_fields():
    """
    Userモデルで必須フィールドが欠けている場合、ValidationErrorが発生することを確認します。
    """
    with pytest.raises(ValidationError) as exc_info:
        schemas.User(username="userwithoutid")
    assert "id" in str(exc_info.value)


@pytest.mark.asyncio
async def test_user_update_valid():
    """
    UserUpdateモデルが有効なデータで正常に作成されることを確認します。
    """
    data = {
        "username": "updateduser",
        "password": "newpassword",
        "is_admin": False
    }
    user_update = schemas.UserUpdate(**data)
    assert user_update.username == "updateduser"
    assert user_update.password == "newpassword"
    assert user_update.is_admin is False


@pytest.mark.asyncio
async def test_user_update_optional_fields():
    """
    UserUpdateモデルで一部のフィールドが省略されている場合、正常に作成されることを確認します。
    """
    data = {
        "username": "partialupdateuser"
    }
    user_update = schemas.UserUpdate(**data)
    assert user_update.username == "partialupdateuser"
    assert user_update.password is None
    assert user_update.is_admin is None


@pytest.mark.asyncio
async def test_user_update_invalid_empty_username():
    """
    UserUpdateモデルでusernameが空文字の場合、ValidationErrorが発生することを確認します。
    """
    with pytest.raises(ValidationError) as exc_info:
        schemas.UserUpdate(username="   ")
    assert "Username must not be empty" in str(exc_info.value)


@pytest.mark.asyncio
async def test_user_update_invalid_empty_password():
    """
    UserUpdateモデルでpasswordが空文字の場合、ValidationErrorが発生することを確認します。
    """
    with pytest.raises(ValidationError) as exc_info:
        schemas.UserUpdate(password=" ")
    assert "Password must not be empty" in str(exc_info.value)


@pytest.mark.asyncio
async def test_token_valid_with_refresh():
    """
    Tokenモデルが有効なデータで正常に作成されることを確認します。
    """
    data = {
        "access_token": "access123",
        "token_type": "bearer",
        "refresh_token": "refresh123"
    }
    token = schemas.Token(**data)
    assert token.access_token == "access123"
    assert token.token_type == "bearer"
    assert token.refresh_token == "refresh123"


@pytest.mark.asyncio
async def test_token_valid_without_refresh():
    """
    Tokenモデルがrefresh_tokenなしで正常に作成されることを確認します。
    """
    data = {
        "access_token": "access123",
        "token_type": "bearer"
    }
    token = schemas.Token(**data)
    assert token.access_token == "access123"
    assert token.token_type == "bearer"
    assert token.refresh_token is None


@pytest.mark.asyncio
async def test_token_invalid_missing_access_token():
    """
    Tokenモデルでaccess_tokenが欠けている場合、ValidationErrorが発生することを確認します。
    """
    data = {
        "token_type": "bearer",
        "refresh_token": "refresh123"
    }
    with pytest.raises(ValidationError) as exc_info:
        schemas.Token(**data)
    assert "access_token" in str(exc_info.value)


@pytest.mark.asyncio
async def test_token_invalid_missing_token_type():
    """
    Tokenモデルでtoken_typeが欠けている場合、ValidationErrorが発生することを確認します。
    """
    data = {
        "access_token": "access123",
        "refresh_token": "refresh123"
    }
    with pytest.raises(ValidationError) as exc_info:
        schemas.Token(**data)
    assert "token_type" in str(exc_info.value)
