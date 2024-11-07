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
│   ├── main.py
│   ├── models.py
│   └── schemas.py
├── docker/
│   ├── Dockerfile
│   └── nginx.conf
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


async def get_user_by_username(db: AsyncSession, username: str) -> Optional[models.User]:
    """
    ユーザー名でユーザーを取得します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    username : str
        取得対象のユーザー名。

    Returns
    -------
    Optional[models.User]
        指定されたユーザー名に一致するユーザーオブジェクト。存在しない場合はNone。
    """
    result = await db.execute(select(models.User).filter(models.User.username == username))
    return result.scalars().first()


async def get_users(db: AsyncSession, skip: int = 0, limit: int = 100) -> List[models.User]:
    """
    全ユーザーを取得します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    skip : int, optional
        スキップするレコード数。デフォルトは0。
    limit : int, optional
        取得するレコード数の上限。デフォルトは100。

    Returns
    -------
    List[models.User]
        取得したユーザーのリスト。
    """
    result = await db.execute(select(models.User).offset(skip).limit(limit))
    return result.scalars().all()


async def create_user(db: AsyncSession, user: schemas.UserCreate, is_admin: bool = False) -> models.User:
    """
    新規ユーザーを作成します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    user : schemas.UserCreate
        作成するユーザーの情報を含むスキーマ。
    is_admin : bool, optional
        作成するユーザーが管理者かどうか。デフォルトはFalse。

    Returns
    -------
    models.User
        作成されたユーザーオブジェクト。
    """
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password, is_admin=is_admin)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


async def get_item(db: AsyncSession, item_id: int) -> Optional[models.Item]:
    """
    アイテムIDで特定のアイテムを取得します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    item_id : int
        取得対象のアイテムID。

    Returns
    -------
    Optional[models.Item]
        指定されたIDに一致するアイテムオブジェクト。存在しない場合はNone。
    """
    result = await db.execute(select(models.Item).filter(models.Item.id == item_id))
    return result.scalars().first()


async def get_items(db: AsyncSession, skip: int = 0, limit: int = 10) -> List[models.Item]:
    """
    複数のアイテムを取得します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    skip : int, optional
        スキップするレコード数。デフォルトは0。
    limit : int, optional
        取得するレコード数の上限。デフォルトは10。

    Returns
    -------
    List[models.Item]
        取得したアイテムのリスト。
    """
    result = await db.execute(select(models.Item).offset(skip).limit(limit))
    return result.scalars().all()


async def create_item(db: AsyncSession, item: schemas.ItemCreate) -> models.Item:
    """
    新しいアイテムを作成します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    item : schemas.ItemCreate
        作成するアイテムの情報を含むスキーマ。

    Returns
    -------
    models.Item
        作成されたアイテムオブジェクト。
    """
    db_item = models.Item(name=item.name)
    db.add(db_item)
    await db.commit()
    await db.refresh(db_item)
    return db_item


async def update_item(db: AsyncSession, item_id: int, item: schemas.ItemCreate) -> Optional[models.Item]:
    """
    アイテムを更新します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    item_id : int
        更新対象のアイテムID。
    item : schemas.ItemCreate
        更新後のアイテム情報を含むスキーマ。

    Returns
    -------
    Optional[models.Item]
        更新されたアイテムオブジェクト。存在しない場合はNone。
    """
    result = await db.execute(select(models.Item).filter(models.Item.id == item_id))
    db_item = result.scalars().first()
    if db_item is None:
        return None
    db_item.name = item.name
    await db.commit()
    await db.refresh(db_item)
    return db_item


async def delete_item(db: AsyncSession, item_id: int) -> Optional[models.Item]:
    """
    アイテムを削除します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    item_id : int
        削除対象のアイテムID。

    Returns
    -------
    Optional[models.Item]
        削除されたアイテムオブジェクト。存在しない場合はNone。
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
from pydantic import BaseModel
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
    name: str  # アイテムの名前


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


class UserCreate(BaseModel):
    """
    ユーザー作成時のモデル

    Attributes
    ----------
    username : str
        ユーザー名。
    password : str
        パスワード。
    """
    username: str  # ユーザー名
    password: str  # パスワード


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
## app/routers/items
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
from fastapi import APIRouter, Depends, HTTPException
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
```
## docker/Dockerfile
```docker/Dockerfile
FROM python:3.11-slim

# 作業ディレクトリの設定
WORKDIR /app

# 必要な環境変数を設定
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 依存関係のインストール
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# アプリケーションコードのコピー
COPY ./app /app/app

# Uvicornでアプリケーションを起動
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```
## docker/nginx.conf
```docker/nginx.conf
events {}

http {
    server {
        listen 80;

        location / {
            proxy_pass http://api:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```
## docker-compose.yml
```docker-compose.yml
version: '3.8'

services:
  db:
    image: postgres:14
    restart: always
    env_file:
      - .env
    environment:
      POSTGRES_USER: ${DATABASE_USER}
      POSTGRES_PASSWORD: ${DATABASE_PASSWORD}
      POSTGRES_DB: ${DATABASE_NAME}
    volumes:
      - db_data:/var/lib/postgresql/data
    ports:
      - "${DATABASE_PORT}:5432"

  api:
    build:
      context: .
      dockerfile: docker/Dockerfile
    restart: always
    env_file:
      - .env
    environment:
      DATABASE_URL: postgresql+asyncpg://${DATABASE_USER}:${DATABASE_PASSWORD}@${DATABASE_HOST}:${DATABASE_PORT}/${DATABASE_NAME}
      SECRET_KEY: ${SECRET_KEY}
      ALGORITHM: ${ALGORITHM}
      ACCESS_TOKEN_EXPIRE_MINUTES: ${ACCESS_TOKEN_EXPIRE_MINUTES}
    depends_on:
      - db
    expose:
      - "${API_PORT}"

  nginx:
    image: nginx:latest
    restart: always
    env_file:
      - .env
    ports:
      - "${NGINX_PORT}:80"
    volumes:
      - ./docker/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - api

volumes:
  db_data:
```
## requirements.txt
```requirements.txt
fastapi
uvicorn[standard]
SQLAlchemy>=1.4
asyncpg
psycopg2-binary
python-dotenv
python-jose[cryptography]
passlib==1.7.4
pydantic>=2.0.0
pydantic-settings
python-multipart
bcrypt==4.0.1
databases
```
## .env
```.env
# Database Configuration
DATABASE_HOST=db
DATABASE_PORT=5432
DATABASE_USER=admin
DATABASE_PASSWORD=my_database_password
DATABASE_NAME=my_database

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# Nginx Configuration
NGINX_PORT=8080

# JWT Configuration
SECRET_KEY=your_secret_key_here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_SECRET_KEY=your_refresh_secret_key_here
REFRESH_TOKEN_EXPIRE_MINUTES=1440

# Initial Admin User
INITIAL_ADMIN_USERNAME=admin
INITIAL_ADMIN_PASSWORD=my_admin_password
```