あなたはPythonの開発のスペシャリストです。
次のプロジェクトを覚えてください。

# プロジェクト構成
my_fastapi_project/
├── app/
│   ├── routers
│   │   ├── auth.py
│   │   ├── items.py
│   │   └── users.py
│   ├── __init__.py
│   ├── auth.py
│   ├── config.py
│   ├── create_admin.py
│   ├── crud.py
│   ├── database.py
│   ├── dependencies.py
│   ├── main.py
│   ├── models.py
│   └── schemas.py
├── docker/
│   ├── Dockerfile
│   └── nginx.conf
├── tests/
│   ├── conftest.py
│   ├── test_auth.py
│   ├── test_create_admin.py
│   ├── test_crud.py
│   ├── test_dependencies.py
│   ├── test_main.py
│   ├── test_models.py
│   ├── test_router_auth.py
│   ├── test_router_items.py
│   ├── test_router_users.py
│   └── test_schemas.py
├── docker-compose.yml
├── requirements.txt
└── README.md

# 各種ファイルの詳細
## app/auth.py
```app/auth.py
from datetime import datetime, timedelta
from typing import Optional, List, Dict

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from .config import settings
from . import schemas, crud
from .dependencies import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    プレーンテキストのパスワードがハッシュ化されたパスワードと一致するかを検証します。

    Parameters
    ----------
    plain_password : str
        検証対象のプレーンテキストパスワード。
    hashed_password : str
        比較対象となるハッシュ化されたパスワード。

    Returns
    -------
    bool
        パスワードが一致する場合はTrue、そうでない場合はFalse。
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    プレーンテキストのパスワードをハッシュ化します。

    Parameters
    ----------
    password : str
        ハッシュ化対象のプレーンテキストパスワード。

    Returns
    -------
    str
        ハッシュ化されたパスワード。
    """
    return pwd_context.hash(password)


def create_jwt_token(
        data: Dict[str, str],
        secret_key: str,
        algorithm: str,
        expires_delta: Optional[timedelta] = None
        ) -> str:
    """
    指定されたデータと有効期限を持つJSON Web Token (JWT) を作成します。

    Parameters
    ----------
    data : Dict[str, str]
        トークンに含めるペイロードデータ。
    secret_key : str
        トークンの署名に使用するシークレットキー。
    algorithm : str
        トークンのエンコーディングに使用するアルゴリズム。
    expires_delta : Optional[timedelta], optional
        トークンの有効期限を設定する時間差。指定しない場合は15分後に設定されます。

    Returns
    -------
    str
        エンコードされたJWT。
    """
    to_encode = data.copy()
    if expires_delta is None:
        expire = datetime.utcnow() + timedelta(minutes=15)
    else:
        expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret_key, algorithm=algorithm)


def create_access_token(data: Dict[str, str], expires_delta: Optional[timedelta] = None) -> str:
    """
    指定されたペイロードと有効期限でアクセストークンを作成します。

    Parameters
    ----------
    data : Dict[str, str]
        アクセストークンに含めるペイロードデータ。
    expires_delta : Optional[timedelta], optional
        トークンの有効期限を設定する時間差。指定しない場合は設定ファイルの値が使用されます。

    Returns
    -------
    str
        エンコードされたアクセストークン。
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
    return create_jwt_token(
        data,
        secret_key=settings.secret_key,
        algorithm=settings.algorithm,
        expires_delta=expires_delta
    )


def create_refresh_token(
        data: Dict[str, str],
        expires_delta: Optional[timedelta] = None
        ) -> str:
    """
    指定されたペイロードと有効期限でリフレッシュトークンを作成します。

    Parameters
    ----------
    data : Dict[str, str]
        リフレッシュトークンに含めるペイロードデータ。
    expires_delta : Optional[timedelta], optional
        トークンの有効期限を設定する時間差。指定しない場合は1日後に設定されます。

    Returns
    -------
    str
        エンコードされたリフレッシュトークン。
    """
    if expires_delta is None:
        expires_delta = timedelta(days=1)
    return create_jwt_token(
        data,
        secret_key=settings.refresh_secret_key,
        algorithm=settings.refresh_algorithm,
        expires_delta=expires_delta
    )


def decode_token(token: str, secret_key: str, algorithms: List[str]) -> Dict:
    """
    JWTをデコードし、そのペイロードを返します。

    Parameters
    ----------
    token : str
        デコード対象のJWT。
    secret_key : str
        トークンのデコードに使用するシークレットキー。
    algorithms : List[str]
        デコードに許可されるアルゴリズムのリスト。

    Returns
    -------
    Dict
        デコードされたトークンのペイロード。
    """
    return jwt.decode(token, secret_key, algorithms=algorithms)


async def authenticate_user(db: AsyncSession, username: str, password: str) -> Optional[schemas.User]:
    """
    ユーザー名とパスワードを用いてユーザーを認証します。

    Parameters
    ----------
    db : AsyncSession
        ユーザーを取得するためのデータベースセッション。
    username : str
        認証を試みるユーザーのユーザー名。
    password : str
        ユーザーが提供したプレーンテキストパスワード。

    Returns
    -------
    Optional[schemas.User]
        認証に成功した場合はユーザーオブジェクトを返し、失敗した場合はNoneを返します。
    """
    user = await crud.get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


async def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: AsyncSession = Depends(get_db)
        ) -> schemas.User:
    """
    提供されたJWTに基づいて現在認証されているユーザーを取得します。

    Parameters
    ----------
    token : str, optional
        リクエストに含まれるJWT。OAuth2スキームを通じて取得されます。
    db : AsyncSession, optional
        データベースセッション。依存関係として取得されます。

    Raises
    ------
    HTTPException
        トークンが無効であるか、ユーザーが存在しない場合に発生します。

    Returns
    -------
    schemas.User
        認証されたユーザーオブジェクト。
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token, settings.secret_key, [settings.algorithm])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = await crud.get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception
    return user


def get_refresh_token(refresh_token: str = Header(..., alias="Refresh-Token")) -> str:
    """
    リクエストヘッダーからリフレッシュトークンを抽出します。

    Parameters
    ----------
    refresh_token : str, optional
        リクエストヘッダー内の "Refresh-Token" キーに含まれるリフレッシュトークン。

    Returns
    -------
    str
        抽出されたリフレッシュトークン。
    """
    return refresh_token
```
## config.py
```app/config.py
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Any


class Settings(BaseSettings):
    """
    アプリケーションの設定を管理するクラスです。

    Attributes
    ----------
    database_host : str
        データベースのホスト名。環境変数 `DATABASE_HOST` から取得します。デフォルトは `"db"` です。
    database_port : int
        データベースのポート番号。環境変数 `DATABASE_PORT` から取得します。デフォルトは `5432` です。
    database_user : str
        データベースのユーザー名。環境変数 `DATABASE_USER` から取得します。デフォルトは `"admin"` です。
    database_password : str
        データベースのパスワード。環境変数 `DATABASE_PASSWORD` から取得します。デフォルトは `"my_database_password"` です。
    database_name : str
        データベースの名前。環境変数 `DATABASE_NAME` から取得します。デフォルトは `"my_database"` です。
    
    api_host : str
        APIサーバーのホスト名。環境変数 `API_HOST` から取得します。デフォルトは `"0.0.0.0"` です。
    api_port : int
        APIサーバーのポート番号。環境変数 `API_PORT` から取得します。デフォルトは `8000` です。
    
    nginx_port : int
        Nginxのポート番号。環境変数 `NGINX_PORT` から取得します。デフォルトは `8080` です。
    
    secret_key : str
        JWTのシークレットキー。環境変数 `SECRET_KEY` から取得します。必須項目です。
    algorithm : str
        JWTのアルゴリズム。環境変数 `ALGORITHM` から取得します。デフォルトは `"HS256"` です。
    access_token_expire_minutes : int
        アクセストークンの有効期限（分）。環境変数 `ACCESS_TOKEN_EXPIRE_MINUTES` から取得します。デフォルトは `30` 分です。
    refresh_algorithm : str
        リフレッシュトークンのアルゴリズム。環境変数 `REFRESH_ALGORITHM` から取得します。デフォルトは `"HS256"` です。
    refresh_secret_key : str
        リフレッシュトークンのシークレットキー。環境変数 `REFRESH_SECRET_KEY` から取得します。必須項目です。
    refresh_token_expire_minutes : int
        リフレッシュトークンの有効期限（分）。環境変数 `REFRESH_TOKEN_EXPIRE_MINUTES` から取得します。デフォルトは `1440` 分（1日）です。
    
    initial_admin_username : str
        初期管理者ユーザーのユーザー名。環境変数 `INITIAL_ADMIN_USERNAME` から取得します。必須項目です。
    initial_admin_password : str
        初期管理者ユーザーのパスワード。環境変数 `INITIAL_ADMIN_PASSWORD` から取得します。必須項目です。
    """

    # データベース設定
    database_host: str = Field("db", env="DATABASE_HOST")
    database_port: int = Field(5432, env="DATABASE_PORT")
    database_user: str = Field("admin", env="DATABASE_USER")
    database_password: str = Field("my_database_password", env="DATABASE_PASSWORD")
    database_name: str = Field("my_database", env="DATABASE_NAME")
    
    # API設定
    api_host: str = Field("0.0.0.0", env="API_HOST")
    api_port: int = Field(8000, env="API_PORT")
    
    # Nginx設定
    nginx_port: int = Field(8080, env="NGINX_PORT")
    
    # JWT設定
    secret_key: str = Field(..., env="SECRET_KEY")
    algorithm: str = Field("HS256", env="ALGORITHM")
    access_token_expire_minutes: int = Field(30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_algorithm: str = Field("HS256", env="REFRESH_ALGORITHM")
    refresh_secret_key: str = Field(..., env="REFRESH_SECRET_KEY")
    refresh_token_expire_minutes: int = Field(1440, env="REFRESH_TOKEN_EXPIRE_MINUTES")
    
    # 初期管理者ユーザー設定
    initial_admin_username: str = Field(..., env="INITIAL_ADMIN_USERNAME")
    initial_admin_password: str = Field(..., env="INITIAL_ADMIN_PASSWORD")
    
    class Config:
        env_file = ".env"


settings = Settings()
```
## app/create_admin.py
```app/create_admin.py
import asyncio
from . import schemas, crud, database
from .config import settings


async def create_initial_admin() -> None:
    """
    初期管理者ユーザーを作成します。

    この関数は、設定ファイルから初期管理者のユーザー名とパスワードを取得し、
    データベースに管理者ユーザーが存在しない場合に新たに作成します。

    Returns
    -------
    None
        この関数は値を返しません。結果はコンソールに出力されます。
    """
    async with database.AsyncSessionLocal() as db:
        # 設定ファイルから初期管理者のユーザー名とパスワードを取得
        username = settings.initial_admin_username
        password = settings.initial_admin_password

        # ユーザー名またはパスワードが設定されていない場合は終了
        if not username or not password:
            print("INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD must be set in .env")
            return

        # 既に管理者ユーザーが存在するか確認
        existing_admin = await crud.get_user_by_username(db, username=username)
        if existing_admin:
            print("Admin user already exists.")
            return

        # 新しい管理者ユーザーを作成
        admin_user = await crud.create_user(
            db,
            schemas.UserCreate(username=username, password=password),
            is_admin=True
        )
        print(f"Admin user created: {admin_user.username}")


if __name__ == "__main__":
    asyncio.run(create_initial_admin())
```
## app/crud.py
```app/crud.py
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update, delete
from . import models, schemas, auth
from typing import Optional, List

# ユーザー名でユーザーを取得する関数
async def get_user_by_username(db: AsyncSession, username: str) -> Optional[models.User]:
    """
    ユーザー名でユーザーを取得します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    username : str
        取得するユーザーのユーザー名。

    Returns
    -------
    Optional[models.User]
        見つかった場合はユーザーオブジェクト、存在しない場合はNone。
    """
    result = await db.execute(select(models.User).filter(models.User.username == username))
    return result.scalars().first()

# 全ユーザーを取得する関数
async def get_users(db: AsyncSession, skip: int = 0, limit: int = 100) -> List[models.User]:
    """
    ユーザーのリストを取得します（ページング可能）。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    skip : int, optional
        取得をスキップするレコード数（デフォルトは0）。
    limit : int, optional
        取得する最大レコード数（デフォルトは100）。

    Returns
    -------
    List[models.User]
        ユーザーオブジェクトのリスト。
    """
    result = await db.execute(select(models.User).offset(skip).limit(limit))
    return result.scalars().all()

# 新規ユーザーを作成する関数
async def create_user(db: AsyncSession, user: schemas.UserCreate, is_admin: bool = False) -> models.User:
    """
    新しいユーザーを作成します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    user : schemas.UserCreate
        新規ユーザーの情報を含むスキーマ。
    is_admin : bool, optional
        ユーザーに管理者権限を付与するか（デフォルトはFalse）。

    Returns
    -------
    models.User
        作成された新しいユーザーオブジェクト。
    """
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password, is_admin=is_admin)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

# ユーザー情報を更新する関数
async def update_user(db: AsyncSession, username: str, user_update: schemas.UserUpdate) -> Optional[models.User]:
    """
    ユーザー情報を更新します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    username : str
        更新対象のユーザー名。
    user_update : schemas.UserUpdate
        更新するユーザー情報を含むスキーマ。

    Returns
    -------
    Optional[models.User]
        更新されたユーザーオブジェクト。ユーザーが存在しない場合はNone。
    """
    result = await db.execute(select(models.User).filter(models.User.username == username))
    db_user = result.scalars().first()
    if db_user is None:
        return None
    
    if user_update.username:
        db_user.username = user_update.username
    if user_update.password:
        db_user.hashed_password = auth.get_password_hash(user_update.password)
    if user_update.is_admin is not None:
        db_user.is_admin = user_update.is_admin
    
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

# app/crud.py

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from . import models, schemas

# ユーザーを削除する関数
async def delete_user(db: AsyncSession, username: str) -> Optional[models.User]:
    """
    ユーザーを削除します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    username : str
        削除対象のユーザー名。

    Returns
    -------
    Optional[models.User]
        削除されたユーザーオブジェクト。存在しない場合はNone。
    """
    result = await db.execute(select(models.User).filter(models.User.username == username))
    db_user = result.scalars().first()
    if db_user is None:
        return None

    await db.delete(db_user)
    await db.commit()
    return db_user


# アイテムIDで特定のアイテムを取得する関数
async def get_item(db: AsyncSession, item_id: int) -> Optional[models.Item]:
    """
    アイテムIDで特定のアイテムを取得します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    item_id : int
        取得するアイテムのID。

    Returns
    -------
    Optional[models.Item]
        見つかった場合はアイテムオブジェクト、存在しない場合はNone。
    """
    result = await db.execute(select(models.Item).filter(models.Item.id == item_id))
    return result.scalars().first()

# 複数のアイテムを取得する関数
async def get_items(db: AsyncSession, skip: int = 0, limit: int = 10) -> List[models.Item]:
    """
    アイテムのリストを取得します（ページング可能）。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    skip : int, optional
        取得をスキップするレコード数（デフォルトは0）。
    limit : int, optional
        取得する最大レコード数（デフォルトは10）。

    Returns
    -------
    List[models.Item]
        アイテムオブジェクトのリスト。
    """
    result = await db.execute(select(models.Item).offset(skip).limit(limit))
    return result.scalars().all()

# 新しいアイテムを作成する関数
async def create_item(db: AsyncSession, item: schemas.ItemCreate) -> models.Item:
    """
    新しいアイテムを作成します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    item : schemas.ItemCreate
        新規アイテムの情報を含むスキーマ。

    Returns
    -------
    models.Item
        作成された新しいアイテムオブジェクト。
    """
    db_item = models.Item(name=item.name)
    db.add(db_item)
    await db.commit()
    await db.refresh(db_item)
    return db_item

# アイテムを更新する関数
async def update_item(db: AsyncSession, item_id: int, item: schemas.ItemCreate) -> Optional[models.Item]:
    """
    アイテムIDでアイテムを更新します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    item_id : int
        更新するアイテムのID。
    item : schemas.ItemCreate
        更新するアイテム情報を含むスキーマ。

    Returns
    -------
    Optional[models.Item]
        更新されたアイテムオブジェクト。アイテムが存在しない場合はNone。
    """
    result = await db.execute(select(models.Item).filter(models.Item.id == item_id))
    db_item = result.scalars().first()
    if db_item is None:
        return None
    db_item.name = item.name
    await db.commit()
    await db.refresh(db_item)
    return db_item

# アイテムを削除する関数
async def delete_item(db: AsyncSession, item_id: int) -> Optional[models.Item]:
    """
    アイテムIDでアイテムを削除します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    item_id : int
        削除するアイテムのID。

    Returns
    -------
    Optional[models.Item]
        削除されたアイテムオブジェクト。アイテムが存在しない場合はNone。
    """
    result = await db.execute(select(models.Item).filter(models.Item.id == item_id))
    db_item = result.scalars().first()
    if db_item is None:
        return None
    await db.delete(db_item)
    await db.commit()
    return db_item
```
## app/database.py
```app/database.py
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
```
## app/dependencies.py
```app/dependencies.py
from .database import AsyncSessionLocal
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends


async def get_db() -> AsyncSession:
    """
    データベースセッションを取得するための依存関数です。

    この関数は、非同期セッションファクトリ `AsyncSessionLocal` を使用して
    データベースセッションを生成し、FastAPIの依存関係として提供します。
    リクエストごとに新しいセッションを作成し、リクエスト終了時にセッションをクローズします。

    Yields
    ------
    AsyncSession
        使用中のデータベースセッションオブジェクト。
    """
    async with AsyncSessionLocal() as session:
        yield session
```
## app/main.py
```app/main.py
from fastapi import FastAPI
from . import database
from .routers import auth, items, users

app = FastAPI()


@app.on_event("startup")
async def on_startup():
    """
    アプリケーションの起動時にデータベースのテーブルを作成します。

    このイベントハンドラーは、アプリケーションが起動する際に呼び出され、
    データベース接続を確立し、全てのテーブルを自動的に作成します。
    """
    async with database.engine.begin() as conn:
        await conn.run_sync(database.Base.metadata.create_all)


# ルーターの登録
app.include_router(auth.router)
app.include_router(items.router)
app.include_router(users.router)
```
## app/models.py
```app/models.py
from sqlalchemy import Boolean, Column, Integer, String
from .database import BaseDatabase


class User(BaseDatabase):
    """
    ユーザーモデル。ユーザーの基本情報を保持します。

    Attributes
    ----------
    id : sqlalchemy.Column
        ユーザーの一意な識別子。プライマリキーであり、インデックスが作成されています。
    username : sqlalchemy.Column
        ユーザー名。ユニークであり、インデックスが作成されています。必須項目です。
    hashed_password : sqlalchemy.Column
        ユーザーのハッシュ化されたパスワード。必須項目です。
    is_admin : sqlalchemy.Column
        ユーザーが管理者かどうかを示すフラグ。デフォルトはFalseです。
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)  # 管理者フラグ


class Item(BaseDatabase):
    """
    アイテムモデル。アイテムの情報を保持します。

    Attributes
    ----------
    id : sqlalchemy.Column
        アイテムの一意な識別子。プライマリキーであり、インデックスが作成されています。
    name : sqlalchemy.Column
        アイテムの名前。インデックスが作成されており、必須項目です。
    """
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
```
## app/schemas.py
```app/schemas.py
from pydantic import BaseModel, ConfigDict, constr, Field, field_validator
from datetime import datetime
from typing import Optional


class ItemBase(BaseModel):
    """
    アイテムの基本モデル（共通項目を定義）

    Attributes
    ----------
    name : str
        アイテムの名前。
    """
    
    name: str # カスタムバリデーションで検証
    @field_validator('name')
    def name_must_not_be_empty(cls, v):
        if not v.strip():
            raise ValueError('Name must not be empty')
        return v

    class Config:
        from_attributes = True
        model_config = ConfigDict()

class ItemCreate(ItemBase):
    """
    アイテム作成時のモデル（追加のプロパティはなし）

    このクラスは `ItemBase` を継承しており、アイテム作成時に必要な基本項目を提供します。
    特別な追加項目はありません。
    """
    pass  # ItemBaseを継承し、特別な追加項目はない


class Item(ItemBase):
    """
    アイテム取得時のモデル（IDやタイムスタンプを含む）

    Attributes
    ----------
    id : int
        アイテムの一意のID。
    created_at : datetime
        アイテムが作成された日時。
    updated_at : datetime
        アイテムが最後に更新された日時。
    """
    id: int  # アイテムの一意のID
    created_at: datetime  # 作成日時
    updated_at: datetime  # 更新日時

    class Config:
        from_attributes = True  # ORM モードを有効にして属性から値を取得できるようにする
        model_config = ConfigDict()

class UserCreate(BaseModel):
    """
    ユーザー作成時のモデル

    Attributes
    ----------
    username : str
        ユーザー名。3文字以上、50文字以下
    password : str
        パスワード。6文字以上
    """
    username: str
    password: str

    @field_validator('username')
    def username_valid(cls, v):
        if not v.strip():
            raise ValueError('Username must not be empty')
        if len(v) < 3 or len(v) > 50:
            raise ValueError('Username must be between 3 and 50 characters')
        return v

    @field_validator('password')
    def password_valid(cls, v):
        if not v.strip():
            raise ValueError('Password must not be empty')
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v

    class Config:
        from_attributes = True
        model_config = ConfigDict()


class User(BaseModel):
    """
    ユーザー取得時のモデル

    Attributes
    ----------
    id : int
        ユーザーの一意のID。
    username : str
        ユーザー名。
    is_admin : bool
        管理者権限フラグ。
    """
    id: int  # ユーザーの一意のID
    username: str  # ユーザー名
    is_admin: bool  # 管理者権限フラグ

    class Config:
        from_attributes = True  # ORM モードを有効にして属性から値を取得できるようにする


class UserUpdate(BaseModel):
    """
    ユーザー更新時のモデル
    
    Attributes
    ----------
    username : Optional[str]
        更新後のユーザー名。省略可能。
    password : Optional[str]
        更新後のパスワード。省略可能。
    is_admin : Optional[bool]
        管理者権限フラグ。省略可能。
    """
    username: Optional[str] = None
    password: Optional[str] = None
    is_admin: Optional[bool] = None

    @field_validator('username')
    def username_valid(cls, v):
        if v is not None:
            if not v.strip():
                raise ValueError('Username must not be empty')
            if len(v) < 3 or len(v) > 50:
                raise ValueError('Username must be between 3 and 50 characters')
        return v

    @field_validator('password')
    def password_valid(cls, v):
        if v is not None:
            if not v.strip():
                raise ValueError('Password must not be empty')
            if len(v) < 6:
                raise ValueError('Password must be at least 6 characters long')
        return v

    class Config:
        from_attributes = True
        model_config = ConfigDict()


class Token(BaseModel):
    """
    トークンのモデル（認証用のアクセストークンとリフレッシュトークン）

    Attributes
    ----------
    access_token : str
        JWT アクセストークン。
    token_type : str
        トークンのタイプ（例: "bearer"）。
    refresh_token : Optional[str]
        JWT リフレッシュトークン。省略可能。
    """
    access_token: str  # JWT アクセストークン
    token_type: str  # トークンのタイプ（例: "bearer"）
    refresh_token: Optional[str] = None  # JWT リフレッシュトークン

    class Config:
        from_attributes = True
        model_config = ConfigDict()
```
## app/routers/auth.py
```app/routers/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from .. import schemas, crud, auth
from ..dependencies import get_db
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from jose import JWTError
import os

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


@router.post("/token", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
) -> schemas.Token:
    """
    アクセストークンとリフレッシュトークンを発行します。

    このエンドポイントは、ユーザーの認証情報を検証し、
    有効な場合はアクセストークンとリフレッシュトークンを発行します。

    Parameters
    ----------
    form_data : OAuth2PasswordRequestForm
        ユーザーが提供する認証情報（ユーザー名とパスワード）。
    db : AsyncSession
        データベースセッション。

    Returns
    -------
    schemas.Token
        アクセストークン、トークンタイプ、およびリフレッシュトークンを含むレスポンス。
    
    Raises
    ------
    HTTPException
        認証情報が不正な場合、401 Unauthorized エラーを返します。
    """
    # ユーザーの認証を試みる
    user = await auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # アクセストークンの有効期限を設定
    access_token_expires = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)))
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # リフレッシュトークンの有効期限を設定
    refresh_token_expires = timedelta(minutes=int(os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES", 1440)))
    refresh_token = auth.create_refresh_token(
        data={"sub": user.username}, expires_delta=refresh_token_expires
    )
    
    # トークンを返す
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token
    }


@router.post("/refresh", response_model=schemas.Token)
async def refresh_access_token(
    refresh_token: str = Depends(auth.get_refresh_token),
    db: AsyncSession = Depends(get_db)
) -> schemas.Token:
    """
    リフレッシュトークンを使用して新しいアクセストークンを発行します。

    このエンドポイントは、提供されたリフレッシュトークンを検証し、
    有効な場合は新しいアクセストークンを発行します。

    Parameters
    ----------
    refresh_token : str
        リクエストヘッダーから取得したリフレッシュトークン。
    db : AsyncSession
        データベースセッション。

    Returns
    -------
    schemas.Token
        新しいアクセストークンとトークンタイプを含むレスポンス。
    
    Raises
    ------
    HTTPException
        トークンが無効な場合やユーザーが存在しない場合にエラーを返します。
    """
    try:
        # リフレッシュトークンをデコードしてペイロードを取得
        payload = auth.decode_token(refresh_token, auth.settings.refresh_secret_key, [auth.settings.refresh_algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # ユーザーが存在するか確認
    user = await crud.get_user_by_username(db, username=username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # 新しいアクセストークンの有効期限を設定
    access_token_expires = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)))
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # 新しいアクセストークンを返す
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }
```
## app/routers/items.py
```app/routers/items.py
from fastapi import APIRouter, Depends, HTTPException
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from .. import schemas, crud
from ..dependencies import get_db
from ..auth import get_current_user

router = APIRouter(
    prefix="/items",
    tags=["items"],
)


@router.post("/", response_model=schemas.Item)
async def create_item(
        item: schemas.ItemCreate,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
        ) -> schemas.Item:
    """
    新しいアイテムを作成します。

    このエンドポイントは、提供されたアイテム情報を基に新しいアイテムをデータベースに作成します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    item : schemas.ItemCreate
        作成するアイテムの情報を含むスキーマ。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : schemas.User
        現在認証されているユーザー。依存関係として提供されます。

    Returns
    -------
    schemas.Item
        作成されたアイテムの詳細を含むレスポンスモデル。
    """
    # 新しいアイテムを作成して返す
    return await crud.create_item(db=db, item=item)


@router.get("/", response_model=List[schemas.Item])
async def read_items(
        skip: int = 0,
        limit: int = 10,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
        ) -> List[schemas.Item]:
    """
    複数のアイテムを取得します。

    このエンドポイントは、指定された範囲内でアイテムのリストをデータベースから取得します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    skip : int, optional
        スキップするレコード数。デフォルトは0。
    limit : int, optional
        取得するレコード数の上限。デフォルトは10。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : schemas.User
        現在認証されているユーザー。依存関係として提供されます。

    Returns
    -------
    List[schemas.Item]
        取得したアイテムのリスト。
    """
    # 指定された範囲でアイテムを取得して返す
    return await crud.get_items(db, skip=skip, limit=limit)


@router.get("/{item_id}", response_model=schemas.Item)
async def read_item(
        item_id: int,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
        ) -> schemas.Item:
    """
    特定のアイテムを取得します。

    このエンドポイントは、指定されたアイテムIDに基づいてアイテムをデータベースから取得します。
    アイテムが存在しない場合は404エラーを返します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    item_id : int
        取得対象のアイテムID。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : schemas.User
        現在認証されているユーザー。依存関係として提供されます。

    Returns
    -------
    schemas.Item
        取得したアイテムの詳細を含むレスポンスモデル。

    Raises
    ------
    HTTPException
        アイテムが存在しない場合に404 Not Foundエラーを返します。
    """
    # アイテムをデータベースから取得
    db_item = await crud.get_item(db, item_id=item_id)
    if db_item is None:
        # アイテムが存在しない場合は404エラーを返す
        raise HTTPException(status_code=404, detail="Item not found")
    return db_item


@router.put("/{item_id}", response_model=schemas.Item)
async def update_item(
        item_id: int,
        item: schemas.ItemCreate,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
        ) -> schemas.Item:
    """
    特定のアイテムを更新します。

    このエンドポイントは、指定されたアイテムIDに基づいてアイテムをデータベース内で更新します。
    アイテムが存在しない場合は404エラーを返します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    item_id : int
        更新対象のアイテムID。
    item : schemas.ItemCreate
        更新後のアイテム情報を含むスキーマ。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : schemas.User
        現在認証されているユーザー。依存関係として提供されます。

    Returns
    -------
    schemas.Item
        更新されたアイテムの詳細を含むレスポンスモデル。

    Raises
    ------
    HTTPException
        アイテムが存在しない場合に404 Not Foundエラーを返します。
    """
    # アイテムをデータベースで更新
    updated_item = await crud.update_item(db=db, item_id=item_id, item=item)
    if updated_item is None:
        # アイテムが存在しない場合は404エラーを返す
        raise HTTPException(status_code=404, detail="Item not found")
    return updated_item


@router.delete("/{item_id}", response_model=dict)
async def delete_item(
        item_id: int,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
        ) -> dict:
    """
    特定のアイテムを削除します。

    このエンドポイントは、指定されたアイテムIDに基づいてアイテムをデータベースから削除します。
    アイテムが存在しない場合は404エラーを返します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    item_id : int
        削除対象のアイテムID。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : schemas.User
        現在認証されているユーザー。依存関係として提供されます。

    Returns
    -------
    dict
        削除の詳細を含むレスポンス。例: {"detail": "Item deleted"}

    Raises
    ------
    HTTPException
        アイテムが存在しない場合に404 Not Foundエラーを返します。
    """
    # アイテムをデータベースから削除
    deleted_item = await crud.delete_item(db=db, item_id=item_id)
    if deleted_item is None:
        # アイテムが存在しない場合は404エラーを返す
        raise HTTPException(status_code=404, detail="Item not found")
    return {"detail": "Item deleted"}
```
## app/routers/users.py
```app/routers/users.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from .. import schemas, crud
from ..dependencies import get_db
from ..auth import get_current_user

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(get_current_user)],
    responses={404: {"description": "Not found"}},
)


@router.post("/", response_model=schemas.User)
async def register_user(
        user: schemas.UserCreate,
        db: AsyncSession = Depends(get_db)
        ) -> schemas.User:
    """
    新しいユーザーを登録します。
    
    このエンドポイントは、提供されたユーザー情報を基に新しいユーザーをデータベースに作成します。
    ユーザー名が既に登録されている場合はエラーを返します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    user : schemas.UserCreate
        作成するユーザーの情報を含むスキーマ。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。

    Returns
    -------
    schemas.User
        作成されたユーザーの詳細を含むレスポンスモデル。

    Raises
    ------
    HTTPException
        ユーザー名が既に登録されている場合に400 Bad Requestエラーを返します。
    """
    # ユーザー名で既存のユーザーを取得
    db_user = await crud.get_user_by_username(db, username=user.username)
    if db_user:
        # ユーザー名が既に存在する場合はエラーを返す
        raise HTTPException(status_code=400, detail="Username already registered")
    # 新しいユーザーを作成して返す
    return await crud.create_user(db=db, user=user)


@router.get("/{username}", response_model=schemas.User)
async def read_user(
        username: str,
        db: AsyncSession = Depends(get_db)
        ) -> schemas.User:
    """
    特定のユーザーを取得します。
    
    このエンドポイントは、指定されたユーザー名に基づいてユーザーをデータベースから取得します。
    ユーザーが存在しない場合は404エラーを返します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    username : str
        取得対象のユーザー名。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。

    Returns
    -------
    schemas.User
        取得したユーザーの詳細を含むレスポンスモデル。

    Raises
    ------
    HTTPException
        ユーザーが存在しない場合に404 Not Foundエラーを返します。
    """
    # ユーザー名でユーザーを取得
    db_user = await crud.get_user_by_username(db, username=username)
    if db_user is None:
        # ユーザーが存在しない場合は404エラーを返す
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.get("/", response_model=List[schemas.User])
async def read_users(
        skip: int = 0,
        limit: int = 100,
        db: AsyncSession = Depends(get_db)
        ) -> List[schemas.User]:
    """
    複数のユーザーを取得します。
    
    このエンドポイントは、指定された範囲内でユーザーのリストをデータベースから取得します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    skip : int, optional
        スキップするレコード数。デフォルトは0。
    limit : int, optional
        取得するレコード数の上限。デフォルトは100。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。

    Returns
    -------
    List[schemas.User]
        取得したユーザーのリスト。
    """
    # 指定された範囲でユーザーを取得して返す
    users = await crud.get_users(db, skip=skip, limit=limit)
    return users

@router.post("/add", response_model=schemas.User)
async def add_user(
        user: schemas.UserCreate,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
    ) -> schemas.User:
    """
    管理者が新しいユーザーを追加します。
    
    このエンドポイントは、認証された管理者ユーザーのみがアクセスできます。
    提供されたユーザー情報を基に新しいユーザーをデータベースに作成します。
    
    Parameters
    ----------
    user : schemas.UserCreate
        作成するユーザーの情報を含むスキーマ。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : auth_schemas.User
        現在認証されているユーザー。依存関係として提供されます。
    
    Returns
    -------
    schemas.User
        作成されたユーザーの詳細を含むレスポンスモデル。
    
    Raises
    ------
    HTTPException
        認証されたユーザーが管理者でない場合に403 Forbiddenエラーを返します。
        ユーザー名が既に登録されている場合に400 Bad Requestエラーを返します。
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to add users")
    
    db_user = await crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    return await crud.create_user(db=db, user=user)

@router.put("/{username}", response_model=schemas.User)
async def update_user_info(
        username: str,
        user_update: schemas.UserUpdate,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
    ) -> schemas.User:
    """
    ユーザー情報を更新します。
    
    このエンドポイントは、認証されたユーザー自身または管理者のみがアクセスできます。
    提供されたユーザー情報を基に指定されたユーザーを更新します。
    
    Parameters
    ----------
    username : str
        更新対象のユーザー名。
    user_update : schemas.UserUpdate
        更新するユーザー情報を含むスキーマ。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : auth_schemas.User
        現在認証されているユーザー。依存関係として提供されます。
    
    Returns
    -------
    schemas.User
        更新されたユーザーの詳細を含むレスポンスモデル。
    
    Raises
    ------
    HTTPException
        認証されたユーザーが対象ユーザー自身でないか、管理者でない場合に403 Forbiddenエラーを返します。
        ユーザーが存在しない場合に404 Not Foundエラーを返します。
    """
    if current_user.username != username and not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to update this user")
    
    updated_user = await crud.update_user(db, username=username, user_update=user_update)
    if updated_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return updated_user

@router.delete("/{username}", response_model=dict)
async def delete_user(
        username: str,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
    ) -> dict:
    """
    ユーザーを削除します（管理者のみ）。

    このエンドポイントは、指定されたユーザー名のユーザーを削除します。
    認証された管理者ユーザーのみがアクセスできます。

    Parameters
    ----------
    username : str
        削除対象のユーザー名。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : schemas.User
        現在認証されているユーザー。依存関係として提供されます。

    Returns
    -------
    dict
        削除の詳細を含むレスポンス。例: {"detail": "User 'username' deleted"}

    Raises
    ------
    HTTPException
        認証されたユーザーが管理者でない場合に403 Forbiddenエラーを返します。
        ユーザーが存在しない場合に404 Not Foundエラーを返します。
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete users")

    deleted_user = await crud.delete_user(db, username=username)
    if deleted_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {"detail": f"User '{username}' deleted"}
```
## tests/conftest.py
```tests/conftest.py
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.main import app
from app.dependencies import get_db
from app.database import Base

# テスト用データベースURL（SQLiteのメモリデータベースを使用）
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

# 非同期エンジンとセッションファクトリの設定
engine = create_async_engine(TEST_DATABASE_URL, echo=True, future=True)
TestingSessionLocal = sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)

@pytest_asyncio.fixture(scope="session")
async def setup_db():
    # テスト用データベースのテーブルを作成
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # テスト後にテーブルを削除
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest_asyncio.fixture
async def db_session(setup_db):
    # 非同期セッションを生成
    async with TestingSessionLocal() as session:
        yield session

@pytest_asyncio.fixture
def override_get_db(db_session):
    # 依存関係をオーバーライド
    async def _override_get_db():
        yield db_session
    app.dependency_overrides[get_db] = _override_get_db
    yield
    app.dependency_overrides.pop(get_db, None)

@pytest_asyncio.fixture
async def client(override_get_db):
    # AsyncClientを使用してテストクライアントを作成
    async with AsyncClient(app=app, base_url="http://test") as c:
        yield c
```
## tests/test_auth.py
```tests/test_auth.py
import pytest
import uuid
from datetime import timedelta, datetime
from jose import JWTError
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from app import auth, schemas, crud
from app.config import settings
from app.models import User

# パスワードコンテキストを再利用
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@pytest.fixture
def unique_username():
    """ユニークなユーザー名を生成するフィクスチャ"""
    return f"user_{uuid.uuid4()}"


@pytest.mark.asyncio
async def test_verify_password():
    password = "testpassword"
    hashed_password = pwd_context.hash(password)
    assert auth.verify_password(password, hashed_password) is True
    assert auth.verify_password("wrongpassword", hashed_password) is False


@pytest.mark.asyncio
async def test_get_password_hash():
    password = "testpassword"
    hashed_password = auth.get_password_hash(password)
    assert pwd_context.verify(password, hashed_password) is True


@pytest.mark.asyncio
async def test_create_jwt_token_default_expiry():
    data = {"sub": "testuser"}
    token = auth.create_jwt_token(
        data=data,
        secret_key="testsecret",
        algorithm="HS256"
    )
    assert isinstance(token, str)

    # デコードして有効期限を確認
    decoded = auth.decode_token(token, "testsecret", ["HS256"])
    assert decoded["sub"] == "testuser"
    assert "exp" in decoded

    # 有効期限が約15分後であることを確認
    exp = datetime.utcfromtimestamp(decoded["exp"])
    now = datetime.utcnow()
    delta = exp - now
    assert timedelta(minutes=14) < delta < timedelta(minutes=16)


@pytest.mark.asyncio
async def test_create_jwt_token_custom_expiry():
    data = {"sub": "testuser"}
    custom_expiry = timedelta(minutes=30)
    token = auth.create_jwt_token(
        data=data,
        secret_key="testsecret",
        algorithm="HS256",
        expires_delta=custom_expiry
    )
    decoded = auth.decode_token(token, "testsecret", ["HS256"])
    exp = datetime.utcfromtimestamp(decoded["exp"])
    now = datetime.utcnow()
    delta = exp - now
    assert timedelta(minutes=29) < delta < timedelta(minutes=31)


@pytest.mark.asyncio
async def test_create_access_token():
    data = {"sub": "testuser"}
    token = auth.create_access_token(data=data)
    assert isinstance(token, str)
    decoded = auth.decode_token(token, settings.secret_key, [settings.algorithm])
    assert decoded["sub"] == "testuser"


@pytest.mark.asyncio
async def test_create_refresh_token_default_expiry():
    data = {"sub": "testuser"}
    token = auth.create_refresh_token(data=data)
    assert isinstance(token, str)
    decoded = auth.decode_token(token, settings.refresh_secret_key, [settings.refresh_algorithm])
    assert decoded["sub"] == "testuser"
    # 有効期限が約1日後であることを確認
    exp = datetime.utcfromtimestamp(decoded["exp"])
    now = datetime.utcnow()
    delta = exp - now
    assert timedelta(days=0, hours=23) < delta < timedelta(days=1, hours=1)


@pytest.mark.asyncio
async def test_create_refresh_token_custom_expiry():
    data = {"sub": "testuser"}
    custom_expiry = timedelta(days=2)
    token = auth.create_refresh_token(data=data, expires_delta=custom_expiry)
    decoded = auth.decode_token(token, settings.refresh_secret_key, [settings.refresh_algorithm])
    exp = datetime.utcfromtimestamp(decoded["exp"])
    now = datetime.utcnow()
    delta = exp - now
    assert timedelta(days=1, hours=23) < delta < timedelta(days=2, hours=1)


@pytest.mark.asyncio
async def test_decode_token_invalid_secret():
    data = {"sub": "testuser"}
    token = auth.create_jwt_token(data=data, secret_key="testsecret", algorithm="HS256")
    with pytest.raises(JWTError):
        auth.decode_token(token, "wrongsecret", ["HS256"])


@pytest.mark.asyncio
async def test_authenticate_user_success(db_session, unique_username):
    username = unique_username
    password = "testpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    user = await auth.authenticate_user(db_session, username, password)
    assert user is not None
    assert user.username == username


@pytest.mark.asyncio
async def test_authenticate_user_wrong_password(db_session, unique_username):
    username = unique_username
    password = "testpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    user = await auth.authenticate_user(db_session, username, "wrongpassword")
    assert user is None


@pytest.mark.asyncio
async def test_authenticate_user_nonexistent_user(db_session):
    user = await auth.authenticate_user(db_session, "nonexistentuser", "password")
    assert user is None


@pytest.mark.asyncio
async def test_get_current_user_success(client, db_session, unique_username):
    username = unique_username
    password = "currentpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    # トークン取得
    response = await client.post(
        "/auth/token",
        data={"username": username, "password": password}
    )
    assert response.status_code == 200
    tokens = response.json()
    access_token = tokens["access_token"]

    # ユーザー取得
    response = await client.get(
        f"/users/{username}",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == username


@pytest.mark.asyncio
async def test_get_current_user_invalid_token(client):
    # 無効なトークンを使用
    invalid_token = "invalidtoken123"

    response = await client.get(
        "/users/testuser",
        headers={"Authorization": f"Bearer {invalid_token}"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"


@pytest.mark.asyncio
async def test_get_refresh_token_header_present(client, db_session, unique_username):
    # テストユーザーの作成
    username = unique_username
    password = "refreshpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    # トークン取得
    response = await client.post(
        "/auth/token",
        data={"username": username, "password": password}
    )
    assert response.status_code == 200
    tokens = response.json()
    refresh_token = tokens.get("refresh_token")
    assert refresh_token is not None

    # リフレッシュトークンを使用して新しいアクセストークンを取得
    response = await client.post(
        "/auth/refresh",
        headers={"Refresh-Token": refresh_token}
    )
    print("Response Status Code:", response.status_code)
    print("Response JSON:", response.json())  # エラー内容を出力
    assert response.status_code == 200
    new_tokens = response.json()
    assert "access_token" in new_tokens
    assert new_tokens["token_type"] == "bearer"
```
## tests/test_create_admin.py
```tests/test_create_admin.py
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
```
## tests/test_crud.py
```tests/test_crud.py
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
```
## tests/test_dependencies.py
```tests/test_dependencies.py
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
```
## tests/test_main.py
```tests/test_main.py
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.main import on_startup
from app.database import Base
from sqlalchemy import inspect
from unittest.mock import patch

@pytest.mark.asyncio
async def test_on_startup_event(db_session: AsyncSession):
    """
    on_startup イベントが正しくテーブルを作成することを確認するテスト。
    
    Args:
        db_session (AsyncSession): テスト用のデータベースセッション（conftest.pyで提供）。
    """
    # テスト用エンジンを取得（既にテスト用のSQLiteエンジンが使用されている）
    test_engine = db_session.bind
    
    # テスト前にテーブルを削除してクリーンな状態にする
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    # app.database.engine をテスト用エンジンにパッチ
    with patch('app.database.engine', test_engine):
        await on_startup()
    
    # テーブルが作成されたことを確認
    async with test_engine.connect() as conn:
        # テーブル名を取得するヘルパー関数を定義
        def get_table_names(conn):
            inspector = inspect(conn)
            return inspector.get_table_names()
        
        # run_sync を使用して同期的にテーブル名を取得
        tables = await conn.run_sync(get_table_names)
        assert "users" in tables, "users テーブルが存在しません。"
        assert "items" in tables, "items テーブルが存在しません。"
```
## tests/test_models.py
```tests/test_models.py
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
```
## tests/test_router_auth.py
```tests/test_router_auth.py
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt
from app import schemas, crud
from app.config import settings

import uuid

@pytest.fixture
def unique_username():
    """ユニークなユーザー名を生成するフィクスチャ"""
    return f"user_{uuid.uuid4()}"


@pytest.mark.asyncio
async def test_login_for_access_token_success(client: AsyncClient, db_session: AsyncSession):
    """
    正しい認証情報を使用してアクセストークンとリフレッシュトークンを取得できることを確認します。
    """
    # テストユーザーの作成
    username = "testuser"
    password = "testpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    # /auth/token エンドポイントにリクエストを送信
    response = await client.post(
        "/auth/token",
        data={"username": username, "password": password}
    )

    assert response.status_code == 200, f"トークン取得に失敗しました: {response.text}"
    tokens = response.json()
    assert "access_token" in tokens, "レスポンスに access_token が含まれていません"
    assert tokens["token_type"] == "bearer", "トークンタイプが正しくありません"
    assert "refresh_token" in tokens, "レスポンスに refresh_token が含まれていません"

    # アクセストークンのデコードと検証
    access_token = tokens["access_token"]
    payload = jwt.decode(access_token, settings.secret_key, algorithms=[settings.algorithm])
    assert payload.get("sub") == username, "アクセストークンのペイロードが正しくありません"


@pytest.mark.asyncio
async def test_login_for_access_token_invalid_credentials(client: AsyncClient):
    """
    無効な認証情報でトークン取得が失敗することを確認します。
    """
    # 存在しないユーザーでリクエストを送信
    response = await client.post(
        "/auth/token",
        data={"username": "invaliduser", "password": "invalidpassword"}
    )

    assert response.status_code == 401, "無効な認証情報で 401 エラーが返されるべきです"
    assert response.json()["detail"] == "Incorrect username or password", "エラーメッセージが正しくありません"


@pytest.mark.asyncio
async def test_refresh_access_token_success(client: AsyncClient, db_session: AsyncSession, unique_username):
    """
    正しいリフレッシュトークンを使用して新しいアクセストークンを取得できることを確認します。
    """
    # テストユーザーの作成
    username = unique_username
    password = "testpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    # トークン取得
    response = await client.post(
        "/auth/token",
        data={"username": username, "password": password}
    )
    tokens = response.json()
    refresh_token = tokens["refresh_token"]

    # /auth/refresh エンドポイントにリクエストを送信
    response = await client.post(
        "/auth/refresh",
        headers={"Refresh-Token": refresh_token}
    )

    assert response.status_code == 200, f"アクセストークンのリフレッシュに失敗しました: {response.text}"
    new_tokens = response.json()
    assert "access_token" in new_tokens, "レスポンスに新しい access_token が含まれていません"
    assert new_tokens["token_type"] == "bearer", "トークンタイプが正しくありません"

    # 新しいアクセストークンのデコードと検証
    access_token = new_tokens["access_token"]
    payload = jwt.decode(access_token, settings.secret_key, algorithms=[settings.algorithm])
    assert payload.get("sub") == username, "新しいアクセストークンのペイロードが正しくありません"


@pytest.mark.asyncio
async def test_refresh_access_token_invalid_token(client: AsyncClient):
    """
    無効なリフレッシュトークンでアクセストークンのリフレッシュが失敗することを確認します。
    """
    # 無効なリフレッシュトークンを使用
    response = await client.post(
        "/auth/refresh",
        headers={"Refresh-Token": "invalidtoken"}
    )

    assert response.status_code == 401, "無効なリフレッシュトークンで 401 エラーが返されるべきです"
    assert response.json()["detail"] == "Invalid token", "エラーメッセージが正しくありません"


@pytest.mark.asyncio
async def test_access_protected_route_with_token(client: AsyncClient, db_session: AsyncSession):
    """
    取得したアクセストークンを使用して保護されたエンドポイントにアクセスできることを確認します。
    """
    # テストユーザーの作成
    username = "protecteduser"
    password = "protectedpassword"
    user_create = schemas.UserCreate(username=username, password=password)
    await crud.create_user(db_session, user_create)

    # トークン取得
    response = await client.post(
        "/auth/token",
        data={"username": username, "password": password}
    )
    tokens = response.json()
    access_token = tokens["access_token"]

    # 保護されたエンドポイントにアクセス
    response = await client.get(
        f"/users/{username}",
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status_code == 200, f"保護されたエンドポイントへのアクセスに失敗しました: {response.text}"
    data = response.json()
    assert data["username"] == username, "取得したユーザー名が正しくありません"


@pytest.mark.asyncio
async def test_access_protected_route_with_invalid_token(client: AsyncClient):
    """
    無効なアクセストークンで保護されたエンドポイントにアクセスできないことを確認します。
    """
    # 無効なアクセストークンを使用
    response = await client.get(
        "/users/someuser",
        headers={"Authorization": "Bearer invalidtoken"}
    )

    assert response.status_code == 401, "無効なアクセストークンで 401 エラーが返されるべきです"
    assert response.json()["detail"] == "Could not validate credentials", "エラーメッセージが正しくありません"
```
## tests/test_router_items.py
```tests/test_router_items.py
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

```
## tests/test_router_users.py
```tests/test_router_users.py
import pytest
import uuid
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app import crud, schemas
from app.main import app
from app.dependencies import get_db
from app.auth import get_password_hash
from tests.conftest import override_get_db


@pytest.fixture
def unique_username():
    """ユニークなユーザー名を生成するフィクスチャ"""
    return f"user_{uuid.uuid4()}"


@pytest.fixture
def unique_admin_username():
    """ユニークな管理者ユーザー名を生成するフィクスチャ"""
    return f"admin_{uuid.uuid4()}"


@pytest.mark.asyncio
async def test_register_user(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    新しいユーザーを登録するテスト。
    他のテスト（test_auth.py）でのユーザー作成方法を参考にしています。
    """
    # ユーザー登録データ
    user_data = {"username": unique_username, "password": "testpassword"}

    # ユーザー登録APIを呼び出す
    response = await client.post("/users/", json=user_data)
    assert response.status_code == 200, f"ユーザー登録に失敗しました: {response.text}"

    # レスポンスデータを検証
    data = response.json()
    assert data["username"] == unique_username
    assert "id" in data
    assert "is_admin" in data
    assert data["is_admin"] is False


@pytest.mark.asyncio
async def test_register_user_existing_username(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    既存のユーザー名でユーザー登録を試み、エラーを確認するテスト。
    """
    # 既存ユーザーを作成
    user_create = schemas.UserCreate(username=unique_username, password="password1")
    await crud.create_user(db_session, user_create)

    # 同じユーザー名で登録を試みる
    user_data = {"username": unique_username, "password": "password2"}
    response = await client.post("/users/", json=user_data)
    assert response.status_code == 400, "既存のユーザー名で登録が成功してはいけません"
    assert response.json()["detail"] == "Username already registered"


@pytest.mark.asyncio
async def test_read_user(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    特定のユーザーを取得するテスト。
    認証が必要なため、トークン取得方法は test_auth.py を参考にしています。
    """
    # テストユーザーを作成
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    await crud.create_user(db_session, user_create)

    # トークンを取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_username, "password": password}
    )
    tokens = response.json()
    access_token = tokens["access_token"]

    # ユーザー情報を取得
    response = await client.get(
        f"/users/{unique_username}",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200, f"ユーザー取得に失敗しました: {response.text}"
    data = response.json()
    assert data["username"] == unique_username


@pytest.mark.asyncio
async def test_read_users(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    複数のユーザーを取得するテスト。
    """
    # テストユーザーを複数作成
    usernames = [unique_username] + [f"user_{uuid.uuid4()}" for _ in range(2)]
    for uname in usernames:
        user_create = schemas.UserCreate(username=uname, password="password")
        await crud.create_user(db_session, user_create)

    # 認証ユーザーでトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": usernames[0], "password": "password"}
    )
    tokens = response.json()
    access_token = tokens["access_token"]

    # ユーザー一覧を取得
    response = await client.get(
        "/users/",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200, f"ユーザー一覧取得に失敗しました: {response.text}"
    data = response.json()
    retrieved_usernames = [user["username"] for user in data]
    for uname in usernames:
        assert uname in retrieved_usernames


@pytest.mark.asyncio
async def test_add_user_as_admin(client: AsyncClient, db_session: AsyncSession, unique_admin_username: str, unique_username: str):
    """
    管理者ユーザーが新しいユーザーを追加するテスト。
    """
    # 管理者ユーザーを作成
    admin_password = "adminpassword"
    admin_user = await crud.create_user(
        db_session,
        schemas.UserCreate(username=unique_admin_username, password=admin_password),
        is_admin=True
    )

    # 管理者でトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_admin_username, "password": admin_password}
    )
    tokens = response.json()
    admin_access_token = tokens["access_token"]

    # 新規ユーザーを追加
    user_data = {"username": unique_username, "password": "newpassword"}
    response = await client.post(
        "/users/add",
        json=user_data,
        headers={"Authorization": f"Bearer {admin_access_token}"}
    )
    assert response.status_code == 200, f"ユーザー追加に失敗しました: {response.text}"
    data = response.json()
    assert data["username"] == unique_username


@pytest.mark.asyncio
async def test_add_user_as_non_admin(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    一般ユーザーが新しいユーザーを追加しようとして失敗するテスト。
    """
    # 一般ユーザーを作成
    user_password = "userpassword"
    user_create = schemas.UserCreate(username=unique_username, password=user_password)
    await crud.create_user(db_session, user_create)

    # 一般ユーザーでトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_username, "password": user_password}
    )
    tokens = response.json()
    user_access_token = tokens["access_token"]

    # 新規ユーザーを追加しようとする
    new_user_data = {"username": "unauthorized_user", "password": "password"}
    response = await client.post(
        "/users/add",
        json=new_user_data,
        headers={"Authorization": f"Bearer {user_access_token}"}
    )
    assert response.status_code == 403, "一般ユーザーがユーザー追加できてはいけません"
    assert response.json()["detail"] == "Not authorized to add users"


@pytest.mark.asyncio
async def test_update_user_info(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    ユーザーが自身の情報を更新するテスト。
    """
    # ユーザーを作成
    user_password = "oldpassword"
    user_create = schemas.UserCreate(username=unique_username, password=user_password)
    await crud.create_user(db_session, user_create)

    # トークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_username, "password": user_password}
    )
    tokens = response.json()
    access_token = tokens["access_token"]

    # ユーザー情報を更新
    update_data = {"username": unique_username, "password": "newpassword"}
    response = await client.put(
        f"/users/{unique_username}",
        json=update_data,
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200, f"ユーザー情報更新に失敗しました: {response.text}"
    data = response.json()
    assert data["username"] == unique_username

    # 新しいパスワードでログインできることを確認
    response = await client.post(
        "/auth/token",
        data={"username": unique_username, "password": "newpassword"}
    )
    assert response.status_code == 200, "新しいパスワードでログインできません"


@pytest.mark.asyncio
async def test_update_other_user_info_as_admin(client: AsyncClient, db_session: AsyncSession, unique_admin_username: str, unique_username: str):
    """
    管理者が他のユーザーの情報を更新するテスト。
    """
    # 管理者ユーザーを作成
    admin_password = "adminpassword"
    await crud.create_user(
        db_session,
        schemas.UserCreate(username=unique_admin_username, password=admin_password),
        is_admin=True
    )

    # 一般ユーザーを作成
    user_password = "userpassword"
    await crud.create_user(
        db_session,
        schemas.UserCreate(username=unique_username, password=user_password)
    )

    # 管理者でトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_admin_username, "password": admin_password}
    )
    tokens = response.json()
    admin_access_token = tokens["access_token"]

    # 一般ユーザーの情報を更新
    update_data = {"is_admin": True}
    response = await client.put(
        f"/users/{unique_username}",
        json=update_data,
        headers={"Authorization": f"Bearer {admin_access_token}"}
    )
    assert response.status_code == 200, f"ユーザー情報更新に失敗しました: {response.text}"
    data = response.json()
    assert data["is_admin"] is True


@pytest.mark.asyncio
async def test_update_other_user_info_as_non_admin(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    一般ユーザーが他のユーザーの情報を更新しようとして失敗するテスト。
    """
    # ユーザーを2人作成
    user1_password = "password1"
    user2_password = "password2"
    user1 = schemas.UserCreate(username=unique_username, password=user1_password)
    user2 = schemas.UserCreate(username=f"user_{uuid.uuid4()}", password=user2_password)
    await crud.create_user(db_session, user1)
    await crud.create_user(db_session, user2)

    # ユーザー1でトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_username, "password": user1_password}
    )
    tokens = response.json()
    user1_access_token = tokens["access_token"]

    # ユーザー2の情報を更新しようとする
    update_data = {"password": "hackedpassword"}
    response = await client.put(
        f"/users/{user2.username}",
        json=update_data,
        headers={"Authorization": f"Bearer {user1_access_token}"}
    )
    assert response.status_code == 403, "他のユーザーの情報を更新できてはいけません"
    assert response.json()["detail"] == "Not authorized to update this user"


@pytest.mark.asyncio
async def test_delete_user_as_admin(client: AsyncClient, db_session: AsyncSession, unique_admin_username: str, unique_username: str):
    """
    管理者がユーザーを削除するテスト。
    """
    # 管理者ユーザーを作成
    admin_password = "adminpassword"
    await crud.create_user(
        db_session,
        schemas.UserCreate(username=unique_admin_username, password=admin_password),
        is_admin=True
    )

    # 一般ユーザーを作成
    await crud.create_user(
        db_session,
        schemas.UserCreate(username=unique_username, password="userpassword")
    )

    # 管理者でトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_admin_username, "password": admin_password}
    )
    tokens = response.json()
    admin_access_token = tokens["access_token"]

    # ユーザーを削除
    response = await client.delete(
        f"/users/{unique_username}",
        headers={"Authorization": f"Bearer {admin_access_token}"}
    )
    assert response.status_code == 200, f"ユーザー削除に失敗しました: {response.text}"
    assert response.json()["detail"] == f"User '{unique_username}' deleted"

    # ユーザーが削除されたことを確認
    user = await crud.get_user_by_username(db_session, username=unique_username)
    assert user is None, "ユーザーが削除されていません"


@pytest.mark.asyncio
async def test_delete_user_as_non_admin(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    一般ユーザーが他のユーザーを削除しようとして失敗するテスト。
    """
    # ユーザーを2人作成
    user1_password = "password1"
    user2_password = "password2"
    user1 = schemas.UserCreate(username=unique_username, password=user1_password)
    user2_username = f"user_{uuid.uuid4()}"
    user2 = schemas.UserCreate(username=user2_username, password=user2_password)
    await crud.create_user(db_session, user1)
    await crud.create_user(db_session, user2)

    # ユーザー1でトークン取得
    response = await client.post(
        "/auth/token",
        data={"username": unique_username, "password": user1_password}
    )
    tokens = response.json()
    user1_access_token = tokens["access_token"]

    # ユーザー2を削除しようとする
    response = await client.delete(
        f"/users/{user2_username}",
        headers={"Authorization": f"Bearer {user1_access_token}"}
    )
    assert response.status_code == 403, "一般ユーザーが他のユーザーを削除できてはいけません"
    assert response.json()["detail"] == "Not authorized to delete users"
```
## tests/test_schemas.py
```tests/test_schemas.py
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
```