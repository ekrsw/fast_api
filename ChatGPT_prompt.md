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
from sqlalchemy.orm import Session

from .config import settings
from . import schemas, crud
from .dependencies import get_db

# パスワードハッシュの設定
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 パスワード認証を設定
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    平文のパスワードとハッシュ化されたパスワードを比較し、一致するか検証します。

    Args:
        plain_password (str): 入力された平文のパスワード。
        hashed_password (str): データベースに保存されているハッシュ化されたパスワード。

    Returns:
        bool: パスワードが一致する場合はTrue、そうでない場合はFalse。
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    パスワードをハッシュ化して保存用に変換します。

    Args:
        password (str): 平文のパスワード。

    Returns:
        str: ハッシュ化されたパスワード。
    """
    return pwd_context.hash(password)


def create_jwt_token(
        data: Dict[str, str],
        secret_key: str,
        algorithm: str,
        expires_delta: Optional[timedelta] = None
        ) -> str:
    """
    JWTトークンを作成し、エンコードします。

    Args:
        data (Dict[str, str]): トークンに含めるペイロードデータ。
        secret_key (str): JWTの秘密鍵。
        algorithm (str): JWTの署名アルゴリズム。
        expires_delta (Optional[timedelta]): トークンの有効期限。

    Returns:
        str: JWT形式のトークン。
    """
    to_encode = data.copy()
    if expires_delta is None:
        # デフォルトの有効期限を15分に設定
        expire = datetime.utcnow() + timedelta(minutes=15)
    else:
        expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret_key, algorithm=algorithm)


def create_access_token(data: Dict[str, str], expires_delta: Optional[timedelta] = None) -> str:
    """
    アクセストークンを作成します。

    Args:
        data (Dict[str, str]): トークンに含めるペイロードデータ。
        expires_delta (Optional[timedelta]): トークンの有効期限。

    Returns:
        str: JWT形式のアクセストークン。
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
    リフレッシュトークンを作成します。

    Args:
        data (Dict[str, str]): トークンに含めるペイロードデータ。
        expires_delta (Optional[timedelta]): トークンの有効期限。

    Returns:
        str: JWT形式のリフレッシュトークン。
    """
    if expires_delta is None:
        # デフォルトの有効期限を1日に設定
        expires_delta = timedelta(days=1)
    return create_jwt_token(
        data,
        secret_key=settings.refresh_secret_key,
        algorithm=settings.refresh_algorithm,
        expires_delta=expires_delta
    )


def decode_token(token: str, secret_key: str, algorithms: List[str]) -> Dict:
    """
    トークンをデコードし、ペイロードデータを取得します。

    Args:
        token (str): デコードするトークン。
        secret_key (str): デコードに使用する秘密鍵。
        algorithms (List[str]): トークンのデコードに使用するアルゴリズム。

    Returns:
        Dict: トークンに含まれるペイロードデータ。
    """
    return jwt.decode(token, secret_key, algorithms=algorithms)


def authenticate_user(db: Session, username: str, password: str) -> Optional[schemas.User]:
    """
    ユーザー名とパスワードでユーザーを認証し、有効な場合はユーザー情報を返します。

    Args:
        db (Session): データベースセッション。
        username (str): 認証するユーザー名。
        password (str): 認証するパスワード。

    Returns:
        Optional[schemas.User]: 認証に成功した場合はユーザーオブジェクト、失敗した場合はNone。
    """
    user = crud.get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
        ) -> schemas.User:
    """
    JWTトークンから現在のユーザーを取得します。トークンが無効な場合は例外を発生させます。

    Args:
        token (str): JWTトークン。
        db (Session): データベースセッション。

    Returns:
        schemas.User: 現在のユーザーオブジェクト。

    Raises:
        HTTPException: トークンが無効な場合に発生。
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

    user = crud.get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception
    return user


def get_refresh_token(refresh_token: str = Header(..., alias="Refresh-Token")) -> str:
    """
    リフレッシュトークンをヘッダーから取得します。

    Args:
        refresh_token (str): ヘッダーから取得したリフレッシュトークン。

    Returns:
        str: リフレッシュトークン。
    """
    return refresh_token
```
## config.py
```app/config.py
# app/config.py
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Any

class Settings(BaseSettings):
    # Database Configuration
    database_host: str = Field("db", env="DATABASE_HOST")
    database_port: int = Field(5432, env="DATABASE_PORT")
    database_user: str = Field("admin", env="DATABASE_USER")
    database_password: str = Field("my_database_password", env="DATABASE_PASSWORD")
    database_name: str = Field("my_database", env="DATABASE_NAME")
    
    # API Configuration
    api_host: str = Field("0.0.0.0", env="API_HOST")
    api_port: int = Field(8000, env="API_PORT")
    
    # Nginx Configuration
    nginx_port: int = Field(8080, env="NGINX_PORT")
    
    # JWT Configuration
    secret_key: str = Field(..., env="SECRET_KEY")
    algorithm: str = Field("HS256", env="ALGORITHM")
    access_token_expire_minutes: int = Field(30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_algorithm: str = Field("HS256", env="REFRESH_ALGORITHM")
    refresh_secret_key: str = Field(..., env="REFRESH_SECRET_KEY")
    refresh_token_expire_minutes: int = Field(1440, env="REFRESH_TOKEN_EXPIRE_MINUTES")
    
    # Initial Admin User
    initial_admin_username: str = Field(..., env="INITIAL_ADMIN_USERNAME")
    initial_admin_password: str = Field(..., env="INITIAL_ADMIN_PASSWORD")
    
    class Config:
        env_file = ".env"

settings = Settings()
```
## app/create_admin.py
```app/create_admin.py
import os
from sqlalchemy.orm import Session
from . import models, schemas, crud, auth, database
from dotenv import load_dotenv

# .env ファイルの読み込み
load_dotenv()

# 初期管理者アカウントを作成する関数
def create_initial_admin() -> None:
    """
    初期管理者アカウントを作成します。
    環境変数からユーザー名とパスワードを取得し、既存の管理者がいない場合のみ新たに作成します。
    """
    db = database.SessionLocal()
    username = os.getenv("INITIAL_ADMIN_USERNAME")
    password = os.getenv("INITIAL_ADMIN_PASSWORD")

    # ユーザー名やパスワードが設定されていない場合はエラーメッセージを表示し終了
    if not username or not password:
        print("INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD must be set in .env")
        return

    # 既に管理者が存在するか確認
    existing_admin = crud.get_user_by_username(db, username=username)
    if existing_admin:
        print("Admin user already exists.")
        return

    # 管理者ユーザーを作成
    admin_user = crud.create_user(
        db,
        schemas.UserCreate(username=username, password=password),
        is_admin=True
    )
    print(f"Admin user created: {admin_user.username}")

# スクリプトが直接実行された場合、create_initial_admin関数を呼び出して管理者を作成
if __name__ == "__main__":
    create_initial_admin()
```
## app/crud.py
```app/crud.py
from sqlalchemy.orm import Session
from . import models, schemas, auth
from typing import Optional, List

# ユーザー名でユーザーを取得する関数
def get_user_by_username(db: Session, username: str) -> Optional[models.User]:
    """
    指定されたユーザー名に一致するユーザーをデータベースから取得します。

    Args:
        db (Session): データベースセッション。
        username (str): 検索対象のユーザー名。

    Returns:
        Optional[models.User]: ユーザーが見つかった場合はそのユーザーオブジェクト、見つからない場合はNone。
    """
    return db.query(models.User).filter(models.User.username == username).first()

# 全ユーザーを取得する関数
def get_users(db: Session, skip: int = 0, limit: int = 100) -> List[models.User]:
    """
    全てのユーザーを取得します。

    Args:
        db (Session): データベースセッション。
        skip (int, optional): スキップするユーザー数。デフォルトは0。
        limit (int, optional): 取得するユーザー数の上限。デフォルトは100。

    Returns:
        List[models.User]: ユーザーのリスト。
    """
    return db.query(models.User).offset(skip).limit(limit).all()

# 新規ユーザーを作成する関数
def create_user(db: Session, user: schemas.UserCreate, is_admin: bool = False) -> models.User:
    """
    新しいユーザーをデータベースに作成します。パスワードはハッシュ化されます。

    Args:
        db (Session): データベースセッション。
        user (schemas.UserCreate): 作成するユーザーのデータを含むUserCreateスキーマ。
        is_admin (bool, optional): ユーザーが管理者かどうかを示すブール値。デフォルトはFalse。

    Returns:
        models.User: 作成されたユーザーオブジェクト。
    """
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password, is_admin=is_admin)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# アイテムIDで特定のアイテムを取得する関数
def get_item(db: Session, item_id: int) -> Optional[models.Item]:
    """
    指定されたIDに一致するアイテムをデータベースから取得します。

    Args:
        db (Session): データベースセッション。
        item_id (int): 検索対象のアイテムID。

    Returns:
        Optional[models.Item]: アイテムが見つかった場合はそのアイテムオブジェクト、見つからない場合はNone。
    """
    return db.query(models.Item).filter(models.Item.id == item_id).first()

# 複数のアイテムを取得する関数
def get_items(db: Session, skip: int = 0, limit: int = 10) -> List[models.Item]:
    """
    指定されたオフセットと制限で、データベースから複数のアイテムを取得します。

    Args:
        db (Session): データベースセッション。
        skip (int, optional): スキップするアイテム数。デフォルトは0。
        limit (int, optional): 取得するアイテム数の制限。デフォルトは10。

    Returns:
        List[models.Item]: アイテムのリスト。
    """
    return db.query(models.Item).offset(skip).limit(limit).all()

# 新しいアイテムを作成する関数
def create_item(db: Session, item: schemas.ItemCreate) -> models.Item:
    """
    新しいアイテムをデータベースに作成します。

    Args:
        db (Session): データベースセッション。
        item (schemas.ItemCreate): 作成するアイテムのデータを含むItemCreateスキーマ。

    Returns:
        models.Item: 作成されたアイテムオブジェクト。
    """
    db_item = models.Item(name=item.name)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item

# アイテムを更新する関数
def update_item(db: Session, item_id: int, item: schemas.ItemCreate) -> Optional[models.Item]:
    """
    指定されたIDのアイテムを更新します。

    Args:
        db (Session): データベースセッション。
        item_id (int): 更新対象のアイテムID。
        item (schemas.ItemCreate): 新しいアイテムデータを含むItemCreateスキーマ。

    Returns:
        Optional[models.Item]: 更新されたアイテムオブジェクト。アイテムが見つからない場合はNone。
    """
    db_item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if db_item is None:
        return None
    db_item.name = item.name
    db.commit()
    db.refresh(db_item)
    return db_item

# アイテムを削除する関数
def delete_item(db: Session, item_id: int) -> Optional[models.Item]:
    """
    指定されたIDのアイテムをデータベースから削除します。

    Args:
        db (Session): データベースセッション。
        item_id (int): 削除対象のアイテムID。

    Returns:
        Optional[models.Item]: 削除されたアイテムオブジェクト。アイテムが見つからない場合はNone。
    """
    db_item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if db_item is None:
        return None
    db.delete(db_item)
    db.commit()
    return db_item
```
## app/database.py
```app/database.py
from sqlalchemy import create_engine, Column, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import settings

DATABASE_URL = f"postgresql://{settings.database_user}:{settings.database_password}@{settings.database_host}:{settings.database_port}/{settings.database_name}"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class BaseDatabase(Base):
    __abstract__ = True
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
```
## app/main.py
```app/main.py
from fastapi import FastAPI
from . import database
from .routers import auth, items, users

# FastAPI アプリケーションのインスタンスを作成
app = FastAPI()

# データベースのテーブルを作成
# アプリケーション起動時に、Base クラスに基づいてデータベースにテーブルを作成します
database.Base.metadata.create_all(bind=database.engine)

# 各エンドポイントに対応するルーターをアプリケーションに登録
app.include_router(auth.router)  # 認証関連のルーター
app.include_router(items.router)  # アイテム関連のルーター
app.include_router(users.router)  # ユーザー関連のルーター
```
## app/models.py
```app/models.py
from sqlalchemy import Boolean, Column, Integer, String
from .database import BaseDatabase

class User(BaseDatabase):
    """
    ユーザーモデル。ユーザーの基本情報を保持します。
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)  # 管理者フラグ

class Item(BaseDatabase):
    """
    アイテムモデル。アイテムの情報を保持します。
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
    """
    name: str  # アイテムの名前

class ItemCreate(ItemBase):
    """
    アイテム作成時のモデル（追加のプロパティはなし）
    """
    pass  # ItemBaseを継承し、特別な追加項目はない

class Item(ItemBase):
    """
    アイテム取得時のモデル（IDやタイムスタンプを含む）
    """
    id: int  # アイテムの一意のID
    created_at: datetime  # 作成日時
    updated_at: datetime  # 更新日時

    class Config:
        from_attributes = True  # ORM モードを有効にして属性から値を取得できるようにする

class UserCreate(BaseModel):
    """
    ユーザー作成時のモデル
    """
    username: str  # ユーザー名
    password: str  # パスワード

class User(BaseModel):
    """
    ユーザー取得時のモデル
    """
    id: int  # ユーザーの一意のID
    username: str  # ユーザー名
    is_admin: bool  # 管理者権限フラグ

    class Config:
        from_attributes = True  # ORM モードを有効にして属性から値を取得できるようにする

class Token(BaseModel):
    """
    トークンのモデル（認証用のアクセストークンとリフレッシュトークン）
    """
    access_token: str  # JWT アクセストークン
    token_type: str  # トークンのタイプ（例: "bearer"）
    refresh_token: Optional[str] = None  # JWT リフレッシュトークン
```
## app/routers/auth.py
```app/routers/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from .. import schemas, crud, auth
from ..dependencies import get_db
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
import os

# 認証用のルーターを設定
router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)

# トークンを発行するためのエンドポイント
@router.post("/token", response_model=schemas.Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
    ) -> schemas.Token:
    """
    ユーザーの認証情報を受け取り、アクセスおよびリフレッシュトークンを発行します。

    Args:
        form_data (OAuth2PasswordRequestForm): ユーザー名とパスワードを含むフォームデータ。
        db (Session): データベースセッション。

    Returns:
        schemas.Token: アクセストークンとリフレッシュトークンを含むトークンデータ。
    """
    # ユーザーの認証
    user = auth.authenticate_user(db, form_data.username, form_data.password)
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

# リフレッシュトークンを使用して新しいアクセストークンを発行するエンドポイント
@router.post("/refresh", response_model=schemas.Token)
def refresh_access_token(
    refresh_token: str = Depends(auth.get_refresh_token),
    db: Session = Depends(get_db)
    ) -> schemas.Token:
    """
    リフレッシュトークンを検証し、新しいアクセストークンを発行します。

    Args:
        refresh_token (str): 有効なリフレッシュトークン。
        db (Session): データベースセッション。

    Returns:
        schemas.Token: 新しいアクセストークンを含むトークンデータ。
    """
    try:
        # リフレッシュトークンをデコードしてユーザー名を取得
        payload = auth.decode_token(refresh_token, auth.REFRESH_SECRET_KEY, [auth.REFRESH_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except auth.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # ユーザーが存在するかを確認
    user = crud.get_user_by_username(db, username=username)
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
from sqlalchemy.orm import Session
from .. import schemas, crud, database, auth
from ..dependencies import get_db
from ..auth import get_current_user

# アイテム関連のルーター設定
router = APIRouter(
    prefix="/items",
    tags=["items"],
)

# 新しいアイテムを作成するエンドポイント
@router.post("/", response_model=schemas.Item)
def create_item(
    item: schemas.ItemCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
    ) -> schemas.Item:
    """
    新しいアイテムを作成します。

    Args:
        item (schemas.ItemCreate): 作成するアイテムのデータ。
        db (Session): データベースセッション。
        current_user (schemas.User): 現在の認証されたユーザー。

    Returns:
        schemas.Item: 作成されたアイテムオブジェクト。
    """
    return crud.create_item(db=db, item=item)

# 複数のアイテムを取得するエンドポイント
@router.get("/", response_model=List[schemas.Item])
def read_items(
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
    ) -> List[schemas.Item]:
    """
    アイテムのリストを取得します。

    Args:
        skip (int, optional): 取得をスキップするアイテムの数。デフォルトは0。
        limit (int, optional): 取得するアイテムの上限数。デフォルトは10。
        db (Session): データベースセッション。
        current_user (schemas.User): 現在の認証されたユーザー。

    Returns:
        List[schemas.Item]: アイテムのリスト。
    """
    return crud.get_items(db, skip=skip, limit=limit)

# 特定のIDのアイテムを取得するエンドポイント
@router.get("/{item_id}", response_model=schemas.Item)
def read_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
    ) -> schemas.Item:
    """
    指定されたIDのアイテムを取得します。

    Args:
        item_id (int): 取得対象のアイテムID。
        db (Session): データベースセッション。
        current_user (schemas.User): 現在の認証されたユーザー。

    Returns:
        schemas.Item: 指定されたアイテムオブジェクト。見つからない場合は404エラー。
    """
    db_item = crud.get_item(db, item_id=item_id)
    if db_item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return db_item

# 特定のIDのアイテムを更新するエンドポイント
@router.put("/{item_id}", response_model=schemas.Item)
def update_item(
    item_id: int,
    item: schemas.ItemCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
    ) -> schemas.Item:
    """
    指定されたIDのアイテムを更新します。

    Args:
        item_id (int): 更新対象のアイテムID。
        item (schemas.ItemCreate): 新しいアイテムデータ。
        db (Session): データベースセッション。
        current_user (schemas.User): 現在の認証されたユーザー。

    Returns:
        schemas.Item: 更新されたアイテムオブジェクト。
    """
    return crud.update_item(db=db, item_id=item_id, item=item)

# 特定のIDのアイテムを削除するエンドポイント
@router.delete("/{item_id}", response_model=dict)
def delete_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
    ) -> dict:
    """
    指定されたIDのアイテムを削除します。

    Args:
        item_id (int): 削除対象のアイテムID。
        db (Session): データベースセッション。
        current_user (schemas.User): 現在の認証されたユーザー。

    Returns:
        dict: 削除完了メッセージを含む辞書オブジェクト。
    """
    crud.delete_item(db=db, item_id=item_id)
    return {"detail": "Item deleted"}
```
## app/routers/users.py
```app/routers/users.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import schemas, crud
from ..dependencies import get_db
from ..auth import get_current_user

# ユーザー関連のルーター設定
router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(get_current_user)],
    responses={404: {"description": "Not found"}},
)

# 新しいユーザーを登録するエンドポイント
@router.post("/", response_model=schemas.User)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)) -> schemas.User:
    """
    新しいユーザーを登録します。

    Args:
        user (schemas.UserCreate): 新しく登録するユーザーのデータ。
        db (Session): データベースセッション。

    Returns:
        schemas.User: 登録されたユーザーオブジェクト。

    Raises:
        HTTPException: ユーザー名が既に登録されている場合、400エラーを返します。
    """
    # ユーザー名が既に存在するか確認
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    # 新規ユーザーを作成
    return crud.create_user(db=db, user=user)

# ユーザー名でユーザー情報を取得するエンドポイント
@router.get("/{username}", response_model=schemas.User)
def read_user(username: str, db: Session = Depends(get_db)) -> schemas.User:
    """
    指定されたユーザー名に一致するユーザー情報を取得します。

    Args:
        username (str): 取得したいユーザーのユーザー名。
        db (Session): データベースセッション。

    Returns:
        schemas.User: 取得したユーザーの情報。

    Raises:
        HTTPException: ユーザーが存在しない場合、404エラーを返します。
    """
    db_user = crud.get_user_by_username(db, username=username)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

# 全ユーザーを取得するエンドポイント
@router.get("/", response_model=List[schemas.User])
def read_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db)
    ) -> List[schemas.User]:
    """
    全ユーザーを取得します。

    Args:
        skip (int, optional): スキップするユーザー数。デフォルトは0。
        limit (int, optional): 取得するユーザー数の上限。デフォルトは100。
        db (Session): データベースセッション。

    Returns:
        List[schemas.User]: ユーザーのリスト。
    """
    users = crud.get_users(db, skip=skip, limit=limit)
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
      DATABASE_URL: postgresql://${DATABASE_USER}:${DATABASE_PASSWORD}@${DATABASE_HOST}:${DATABASE_PORT}/${DATABASE_NAME}
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
SQLAlchemy
psycopg2-binary
python-dotenv
python-jose[cryptography]
passlib==1.7.4
python-multipart
bcrypt==4.0.1
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