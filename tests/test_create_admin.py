# tests/test_create_admin.py
import pytest
import uuid
from unittest.mock import AsyncMock, patch
from sqlalchemy.exc import IntegrityError

from app import schemas, crud
from app.create_admin import create_initial_admin
from app.models import User  # SQLAlchemyのUserモデルをインポート

@pytest.fixture
def unique_username():
    """ユニークなユーザー名を生成するフィクスチャ"""
    return f"user_{uuid.uuid4()}"

@pytest.mark.asyncio
async def test_create_initial_admin_success(unique_username, db_session, capsys):
    username = unique_username
    password = "securepassword"
    
    # settings をモックして初期管理者のユーザー名とパスワードを設定
    with patch("app.create_admin.settings") as mock_settings:
        mock_settings.initial_admin_username = username
        mock_settings.initial_admin_password = password
        
        # crud.get_user_by_username をモックしてユーザーが存在しないことを返す
        with patch("app.create_admin.crud.get_user_by_username", new=AsyncMock(return_value=None)) as mock_get_user:
            
            # crud.create_user をモックして新しいユーザーオブジェクトを返す
            mock_admin_user = User(
                username=username,
                hashed_password="$2b$12$hashedpassword",
                is_admin=True,
                id=1,
                created_at=None,
                updated_at=None
            )
            with patch("app.create_admin.crud.create_user", new=AsyncMock(return_value=mock_admin_user)) as mock_create_user:
                
                # create_initial_admin 関数を実行
                await create_initial_admin()
                
                # create_user が正しく呼び出されたことを確認
                mock_create_user.assert_awaited_once_with(
                    db_session,
                    schemas.UserCreate(username=username, password=password),
                    is_admin=True
                )
                
                # 出力をキャプチャして確認
                captured = capsys.readouterr()
                assert f"Admin user created: {username}" in captured.out

@pytest.mark.asyncio
async def test_create_initial_admin_already_exists(unique_username, db_session, capsys):
    username = unique_username
    password = "securepassword"
    
    # settings をモックして初期管理者のユーザー名とパスワードを設定
    with patch("app.create_admin.settings") as mock_settings:
        mock_settings.initial_admin_username = username
        mock_settings.initial_admin_password = password
        
        # crud.get_user_by_username をモックして既存のユーザーオブジェクトを返す
        existing_admin = User(
            username=username,
            hashed_password="$2b$12$existinghashedpassword",
            is_admin=True,
            id=1,
            created_at=None,
            updated_at=None
        )
        with patch("app.create_admin.crud.get_user_by_username", new=AsyncMock(return_value=existing_admin)) as mock_get_user:
            
            # crud.create_user をモック（実際には呼ばれないはず）
            with patch("app.create_admin.crud.create_user", new=AsyncMock()) as mock_create_user:
                
                # create_initial_admin 関数を実行
                await create_initial_admin()
                
                # create_user が呼ばれていないことを確認
                mock_create_user.assert_not_awaited()
                
                # 出力をキャプチャして確認
                captured = capsys.readouterr()
                assert "Admin user already exists." in captured.out

@pytest.mark.asyncio
async def test_create_initial_admin_missing_username(db_session, capsys):
    password = "securepassword"
    
    # settings をモックして初期管理者のユーザー名を未設定、パスワードを設定
    with patch("app.create_admin.settings") as mock_settings:
        mock_settings.initial_admin_username = None
        mock_settings.initial_admin_password = password
        
        # create_initial_admin 関数を実行
        await create_initial_admin()
        
        # 出力をキャプチャして確認
        captured = capsys.readouterr()
        assert "INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD must be set in .env" in captured.out

@pytest.mark.asyncio
async def test_create_initial_admin_missing_password(unique_username, db_session, capsys):
    username = unique_username
    
    # settings をモックして初期管理者のユーザー名を設定、パスワードを未設定
    with patch("app.create_admin.settings") as mock_settings:
        mock_settings.initial_admin_username = username
        mock_settings.initial_admin_password = None
        
        # create_initial_admin 関数を実行
        await create_initial_admin()
        
        # 出力をキャプチャして確認
        captured = capsys.readouterr()
        assert "INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD must be set in .env" in captured.out

@pytest.mark.asyncio
async def test_create_initial_admin_create_user_failure(unique_username, db_session, capsys):
    username = unique_username
    password = "securepassword"
    
    # settings をモックして初期管理者のユーザー名とパスワードを設定
    with patch("app.create_admin.settings") as mock_settings:
        mock_settings.initial_admin_username = username
        mock_settings.initial_admin_password = password
        
        # crud.get_user_by_username をモックしてユーザーが存在しないことを返す
        with patch("app.create_admin.crud.get_user_by_username", new=AsyncMock(return_value=None)) as mock_get_user:
            
            # crud.create_user をモックして IntegrityError を発生させる
            with patch("app.create_admin.crud.create_user", new=AsyncMock(side_effect=IntegrityError("Duplicate entry", {}, None))) as mock_create_user:
                
                # create_initial_admin 関数を実行
                await create_initial_admin()
                
                # create_user が正しく呼び出されたことを確認
                mock_create_user.assert_awaited_once_with(
                    db_session,
                    schemas.UserCreate(username=username, password=password),
                    is_admin=True
                )
                
                # 出力をキャプチャして確認
                captured = capsys.readouterr()
                assert f"Admin user '{username}' already exists." in captured.out
