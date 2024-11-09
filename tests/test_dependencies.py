# tests/test_dependencies.py

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession
from app.dependencies import get_db


@pytest.mark.asyncio
async def test_get_db_yields_session():
    """
    `get_db` 関数が `AsyncSession` を正しく提供し、
    セッションが適切にクローズされることを確認します。
    """
    # モックセッションを作成
    mock_session = AsyncMock(spec=AsyncSession)
    mock_session.close = AsyncMock()

    # モックコンテキストマネージャを作成
    mock_context_manager = MagicMock()
    mock_context_manager.__aenter__ = AsyncMock(return_value=mock_session)
    mock_context_manager.__aexit__ = AsyncMock(return_value=None)

    # AsyncSessionLocal をモックして、モックコンテキストマネージャを返すように設定
    mock_async_session_local = MagicMock(return_value=mock_context_manager)

    with patch('app.dependencies.AsyncSessionLocal', mock_async_session_local):
        # `get_db` を呼び出してセッションを取得
        async for session in get_db():
            assert session is mock_session

        # コンテキストマネージャの __aexit__ が呼び出されたことを確認
        mock_context_manager.__aexit__.assert_awaited_once()

        # セッションの close メソッドが呼び出されたことを確認
        mock_session.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_db_multiple_sessions():
    """
    `get_db` 関数が複数回呼び出された際に、
    各呼び出しで新しい `AsyncSession` が提供されることを確認します。
    """
    # モックセッションを2つ作成
    mock_session1 = AsyncMock(spec=AsyncSession)
    mock_session1.close = AsyncMock()
    mock_session2 = AsyncMock(spec=AsyncSession)
    mock_session2.close = AsyncMock()

    # モックコンテキストマネージャを2つ作成
    mock_context_manager1 = MagicMock()
    mock_context_manager1.__aenter__ = AsyncMock(return_value=mock_session1)
    mock_context_manager1.__aexit__ = AsyncMock(return_value=None)

    mock_context_manager2 = MagicMock()
    mock_context_manager2.__aenter__ = AsyncMock(return_value=mock_session2)
    mock_context_manager2.__aexit__ = AsyncMock(return_value=None)

    # AsyncSessionLocal をモックして、2回目の呼び出しで別のコンテキストマネージャを返すように設定
    mock_async_session_local = MagicMock(side_effect=[mock_context_manager1, mock_context_manager2])

    with patch('app.dependencies.AsyncSessionLocal', mock_async_session_local):
        # 最初の呼び出し
        async for session in get_db():
            assert session is mock_session1

        # 2回目の呼び出し
        async for session in get_db():
            assert session is mock_session2

        # 各コンテキストマネージャの __aexit__ が呼び出されたことを確認
        mock_context_manager1.__aexit__.assert_awaited_once()
        mock_context_manager2.__aexit__.assert_awaited_once()

        # 各セッションの close メソッドが呼び出されたことを確認
        mock_session1.close.assert_awaited_once()
        mock_session2.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_get_db_exception_handling():
    """
    `get_db` 関数内で例外が発生した場合に、
    セッションが適切にクローズされることを確認します。
    """
    # モックセッションを作成
    mock_session = AsyncMock(spec=AsyncSession)
    mock_session.close = AsyncMock()

    # モックコンテキストマネージャを作成
    mock_context_manager = MagicMock()
    mock_context_manager.__aenter__ = AsyncMock(return_value=mock_session)
    mock_context_manager.__aexit__ = AsyncMock(return_value=None)

    # AsyncSessionLocal をモックして、モックコンテキストマネージャを返すように設定
    mock_async_session_local = MagicMock(return_value=mock_context_manager)

    with patch('app.dependencies.AsyncSessionLocal', mock_async_session_local):
        # `get_db` を呼び出してセッションを取得
        async_gen = get_db()
        session = await async_gen.__anext__()
        assert session is mock_session

        # 例外を発生させてジェネレータを閉じる
        with pytest.raises(StopAsyncIteration):
            await async_gen.asend(None)  # 正しく例外を発生させる方法

        # コンテキストマネージャの __aexit__ が呼び出されたことを確認
        mock_context_manager.__aexit__.assert_awaited_once()

        # セッションの close メソッドが呼び出されたことを確認
        mock_session.close.assert_awaited_once()
