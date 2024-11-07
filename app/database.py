from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, DateTime, func
from .config import settings

# データベース接続URLの構築
DATABASE_URL = (
    f"postgresql+asyncpg://{settings.database_user}:"
    f"{settings.database_password}@{settings.database_host}:"
    f"{settings.database_port}/{settings.database_name}"
)

# 非同期エンジンの作成
engine = create_async_engine(DATABASE_URL, echo=True, future=True)

# 非同期セッションファクトリの設定
AsyncSessionLocal = sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)

# デクラレーティブベースの作成
Base = declarative_base()


class BaseDatabase(Base):
    """
    すべてのデータベースモデルの基底クラスです。

    このクラスは、作成日時 (`created_at`) と更新日時 (`updated_at`) のカラムを
    各モデルに自動的に追加します。

    Attributes
    ----------
    created_at : sqlalchemy.Column
        レコードの作成日時を格納するカラム。デフォルトで現在時刻が設定され、変更不可です。
    updated_at : sqlalchemy.Column
        レコードの最終更新日時を格納するカラム。デフォルトで現在時刻が設定され、
        レコードが更新されるたびに自動的に更新されます。
    """

    __abstract__ = True

    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
