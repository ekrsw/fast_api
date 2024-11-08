import pytest
import asyncio
from unittest.mock import patch, AsyncMock, ANY
from app.create_admin import create_initial_admin
from app import schemas

@pytest.mark.asyncio
async def test_create_initial_admin_no_username_or_password(capfd):
    """
    初期管理者のユーザー名またはパスワードが設定されていない場合、
    関数は警告メッセージを出力し、ユーザーを作成しない。
    """
    with patch('app.create_admin.settings.initial_admin_username', None), \
         patch('app.create_admin.settings.initial_admin_password', None):
        await create_initial_admin()
        out, err = capfd.readouterr()
        assert "INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD must be set in .env" in out

@pytest.mark.asyncio
async def test_create_initial_admin_user_exists(capfd):
    """
    既に管理者ユーザーが存在する場合、
    関数は警告メッセージを出力し、ユーザーを作成しない。
    """
    with patch('app.create_admin.settings.initial_admin_username', 'admin'), \
         patch('app.create_admin.settings.initial_admin_password', 'password'), \
         patch('app.create_admin.crud.get_user_by_username', AsyncMock(return_value=schemas.User(id=1, username='admin', is_admin=True, hashed_password='hashedpassword'))):
        await create_initial_admin()
        out, err = capfd.readouterr()
        assert "Admin user already exists." in out

@pytest.mark.asyncio
async def test_create_initial_admin_user_created(capfd):
    """
    管理者ユーザーが存在しない場合、
    関数は新しい管理者ユーザーを作成し、確認メッセージを出力する。
    """
    mock_user = schemas.User(id=1, username='admin', is_admin=True, hashed_password='hashedpassword')
    with patch('app.create_admin.settings.initial_admin_username', 'admin'), \
         patch('app.create_admin.settings.initial_admin_password', 'password'), \
         patch('app.create_admin.crud.get_user_by_username', AsyncMock(return_value=None)), \
         patch('app.create_admin.crud.create_user', AsyncMock(return_value=mock_user)):
        await create_initial_admin()
        out, err = capfd.readouterr()
        assert "Admin user created: admin" in out

@pytest.mark.asyncio
async def test_create_initial_admin_partial_credentials(capfd):
    """
    初期管理者のユーザー名またはパスワードが部分的に設定されていない場合、
    関数は警告メッセージを出力し、ユーザーを作成しない。
    """
    # テストケース1: ユーザー名が設定されていない
    with patch('app.create_admin.settings.initial_admin_username', None), \
         patch('app.create_admin.settings.initial_admin_password', 'password'):
        await create_initial_admin()
        out, err = capfd.readouterr()
        assert "INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD must be set in .env" in out

    # テストケース2: パスワードが設定されていない
    with patch('app.create_admin.settings.initial_admin_username', 'admin'), \
         patch('app.create_admin.settings.initial_admin_password', None):
        await create_initial_admin()
        out, err = capfd.readouterr()
        assert "INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD must be set in .env" in out

@pytest.mark.asyncio
async def test_create_initial_admin_crud_create_user_called(capfd):
    """
    管理者ユーザーが存在しない場合、
    `crud.create_user` が正しく呼び出されることを確認する。
    """
    mock_user = schemas.User(id=1, username='admin', is_admin=True, hashed_password='hashedpassword')
    with patch('app.create_admin.settings.initial_admin_username', 'admin'), \
         patch('app.create_admin.settings.initial_admin_password', 'password'), \
         patch('app.create_admin.crud.get_user_by_username', AsyncMock(return_value=None)) as mock_get_user, \
         patch('app.create_admin.crud.create_user', AsyncMock(return_value=mock_user)) as mock_create_user:
        await create_initial_admin()
        mock_get_user.assert_awaited_once()
        mock_create_user.assert_awaited_once_with(
            ANY,  # `db` セッションは実際にはモックされていないため、ANY で許容
            schemas.UserCreate(username='admin', password='password'),
            is_admin=True
        )
        out, err = capfd.readouterr()
        assert "Admin user created: admin" in out
