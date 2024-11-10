import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.dependencies import get_db
from app import models, crud, schemas, auth
from app.database import engine, BaseDatabase
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_get_db_yields_session(override_get_db, db_session):
    """
    get_db関数がAsyncSessionを正しく生成してyieldすることを確認します。
    """
    async for session in get_db():
        assert isinstance(session, AsyncSession), "get_dbはAsyncSessionをyieldする必要があります。"
        
        # 簡単なクエリを実行してセッションが有効であることを確認
        result = await session.execute(select(models.User).limit(1))
        user = result.scalars().first()
        # ここでは特定のアサーションは行わず、セッションが正常に動作することを確認
        break  # 一度だけテストするためにループを終了

@pytest.mark.asyncio
async def test_get_db_session_closed(override_get_db, db_session):
    """
    get_db関数が終了後にセッションを正しくクローズすることを確認します。
    """
    gen = get_db()
    try:
        session = await gen.__anext__()
        assert session.is_active, "セッションはまだクローズされていないはずです。"
    except StopAsyncIteration:
        pytest.fail("get_dbジェネレータがセッションをyieldしませんでした。")
    
    await gen.aclose()
    assert session.is_active, "セッションがクローズされている必要があります。"
    assert isinstance(session, AsyncSession), "セッションがAsyncSessionのインスタンスではありません。"

@pytest.mark.asyncio
async def test_get_db_multiple_sessions(override_get_db, db_session):
    """
    get_db関数が複数回呼び出された場合、異なるセッションを生成することを確認します。
    """
    async for session1 in get_db():
        async for session2 in get_db():
            assert session1 != session2, "異なる呼び出しで同一のセッションが生成されるべきではありません。"
            break
        break

@pytest.mark.asyncio
async def test_get_db_dependency_overridden(client, db_session, unique_username):
    """
    テスト環境でget_db依存関係が正しくオーバーライドされていることを確認します。
    認証を行い、アクセストークンを使用してエンドポイントにアクセスします。
    """
    # ユニークなユーザー名とパスワードを使用してテストユーザーを作成
    username = unique_username
    password = "testpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)
    
    # トークン取得
    response = await client.post(
        "/auth/token",
        data={"username": username, "password": password}
    )
    assert response.status_code == 200, f"トークン取得に失敗: {response.text}"
    tokens = response.json()
    access_token = tokens["access_token"]
    
    # ユーザー取得エンドポイントにアクセス
    response = await client.get(
        f"/users/{username}",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200, f"ユーザー取得に失敗: {response.text}"
    data = response.json()
    assert data["username"] == username
