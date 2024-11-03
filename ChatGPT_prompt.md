あなたはPythonの開発のスペシャリストです。
次のプロジェクトを覚えてください。

# プロジェクト構成
my_fastapi_project/
├── app/
│   ├── __init__.py
│   ├── auth.py
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
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv

# .env ファイルの読み込み
load_dotenv()

# パスワードハッシュの設定
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT 設定
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# パスワードを検証する関数
def verify_password(plain_password, hashed_password):
    """
    引数で受け取った平文のパスワードと、ハッシュ化されたパスワードを比較して、
    一致するかどうかを検証します。
    """
    return pwd_context.verify(plain_password, hashed_password)

# パスワードをハッシュ化する関数
def get_password_hash(password):
    """
    引数で受け取ったパスワードをハッシュ化して返します。
    """
    return pwd_context.hash(password)

# アクセストークンを作成する関数
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    JWT形式のアクセストークンを作成して返します。
    
    args:
    - data: トークンに含めるデータ（例: {"sub": "ユーザー名"}）
    - expires_delta: トークンの有効期限（指定がない場合はデフォルトで15分）

    return:
    - 作成されたJWT形式のアクセストークン
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
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
def create_initial_admin():
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

# ユーザー名でユーザーを取得する関数
def get_user_by_username(db: Session, username: str):
    """
    指定されたユーザー名に一致するユーザーをデータベースから取得します。

    Args:
        db (Session): データベースセッション。
        username (str): 検索対象のユーザー名。

    Returns:
        Optional[models.User]: ユーザーが見つかった場合はそのユーザーオブジェクト、見つからない場合はNone。
    """
    return db.query(models.User).filter(models.User.username == username).first()

# 新規ユーザーを作成する関数
def create_user(db: Session, user: schemas.UserCreate, is_admin: bool = False):
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
```
## app/database.py
```app/database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

# .env ファイルの読み込み
load_dotenv()

# データベース接続設定を環境変数から取得し、デフォルト値を指定
DATABASE_HOST = os.getenv("DATABASE_HOST", "db")  # ホスト名
DATABASE_PORT = os.getenv("DATABASE_PORT", "5432")  # ポート番号
DATABASE_USER = os.getenv("DATABASE_USER", "postgres")  # ユーザー名
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "postgres")  # パスワード
DATABASE_NAME = os.getenv("DATABASE_NAME", "postgres")  # データベース名

# データベース接続URLを生成
DATABASE_URL = f"postgresql://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}"

# SQLAlchemyエンジンを作成して、データベース接続を管理
engine = create_engine(DATABASE_URL)

# セッション作成用のクラスを定義（自動コミットや自動フラッシュは無効）
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 基本のマッピングクラスを作成するためのベースクラスを生成
Base = declarative_base()
```
## app/main.py
```app/main.py
from fastapi import FastAPI, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session
from . import models, schemas, database, auth, crud
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Optional
from datetime import timedelta
import os
from dotenv import load_dotenv

# .env ファイルの読み込み
load_dotenv()

# FastAPI アプリケーションのインスタンスを作成
app = FastAPI()

# データベースのテーブルを作成
models.Base.metadata.create_all(bind=database.engine)

# OAuth2 パスワード認証を設定し、トークンの取得エンドポイントを指定
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# データベース接続の取得
def get_db():
    """
    データベースセッションを取得するための依存関係。

    Yields:
        Session: データベースセッションオブジェクト。
    """
    db = database.SessionLocal()  # セッションを作成
    try:
        yield db  # データベースセッションを呼び出し元に提供
    finally:
        db.close()  # 最後にセッションを閉じる

# ユーザー認証の関数
def authenticate_user(db: Session, username: str, password: str):
    """
    ユーザー名とパスワードを使用してユーザーを認証します。

    Args:
        db (Session): データベースセッション。
        username (str): 認証するユーザー名。
        password (str): 認証するパスワード。

    Returns:
        Union[models.User, bool]: 認証に成功した場合はユーザーオブジェクト、失敗した場合はFalse。
    """
    user = crud.get_user_by_username(db, username)  # ユーザー名でユーザーを取得
    if not user:
        return False  # ユーザーが存在しない場合は False を返す
    if not auth.verify_password(password, user.hashed_password):
        return False  # パスワードが一致しない場合も False を返す
    return user  # 認証成功時にユーザー情報を返す

# アクセストークンの作成
def create_access_token_for_user(data: dict, expires_delta: Optional[timedelta] = None):
    """
    ユーザー用のアクセストークンを作成します。

    Args:
        data (dict): トークンに含めるデータ。
        expires_delta (Optional[timedelta], optional): トークンの有効期限。デフォルトはNone。

    Returns:
        str: 作成されたアクセストークン。
    """
    return auth.create_access_token(data, expires_delta)

# ユーザーの登録エンドポイント
@app.post("/register/", response_model=schemas.User)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    新しいユーザーを登録します。

    Args:
        user (schemas.UserCreate): 登録するユーザーの情報。
        db (Session, optional): データベースセッション。デフォルトはDepends(get_db)。

    Raises:
        HTTPException: ユーザー名が既に登録されている場合。

    Returns:
        schemas.User: 登録されたユーザー情報。
    """
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db=db, user=user)

# ユーザーのログインエンドポイント
@app.post("/token", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    ログインしてアクセストークンとリフレッシュトークンを取得します。

    Args:
        form_data (OAuth2PasswordRequestForm, optional): フォームデータからユーザー名とパスワードを取得。
        db (Session, optional): データベースセッション。

    Raises:
        HTTPException: 認証に失敗した場合。

    Returns:
        dict: アクセストークンとトークンタイプ,リフレッシュトークンを含む辞書。
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)))
    access_token = create_access_token_for_user(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    refresh_token_expires = timedelta(minutes=auth.REFRESH_TOKEN_EXPIRE_MINUTES)
    refresh_token = auth.create_refresh_token(
        data={"sub": user.username}, expires_delta=refresh_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token
    }

# 新しいアクセストークンを取得するためのエンドポイント
@app.post("/refresh", response_model=schemas.Token)
def refresh_access_token(
    refresh_token: str = Header(...),
    db: Session = Depends(get_db)
    ):
    """
    リフレッシュトークンを使用して新しいアクセストークンを取得します。
    """
    try:
        payload = jwt.decode(refresh_token, auth.REFRESH_SECRET_KEY, algorithms=[auth.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="トークンが無効です")
    except JWTError:
        raise HTTPException(status_code=401, detail="トークンが無効です")

    user = crud.get_user_by_username(db, username=username)
    if user is None:
        raise HTTPException(status_code=404, detail="ユーザーが存在しません")

    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token_for_user(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

# 現在のユーザーの取得
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    現在の認証済みユーザーを取得します。

    Args:
        token (str, optional): 認証トークン。
        db (Session, optional): データベースセッション。

    Raises:
        HTTPException: 認証情報の検証に失敗した場合。

    Returns:
        models.User: 現在のユーザーオブジェクト。
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception
    return user

# アイテムの作成エンドポイント
@app.post("/items/", response_model=schemas.Item)
def create_item(
    item: schemas.ItemCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """
    新しいアイテムを作成します。

    Args:
        item (schemas.ItemCreate): 作成するアイテムの情報。
        db (Session, optional): データベースセッション。
        current_user (schemas.User, optional): 現在のユーザー。

    Returns:
        schemas.Item: 作成されたアイテム。
    """
    db_item = models.Item(name=item.name)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item

# アイテムの取得エンドポイント
@app.get("/items/", response_model=List[schemas.Item])
def read_items(
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """
    アイテムのリストを取得します。

    Args:
        skip (int, optional): スキップする件数。デフォルトは0。
        limit (int, optional): 取得する最大件数。デフォルトは10。
        db (Session, optional): データベースセッション。
        current_user (schemas.User, optional): 現在のユーザー。

    Returns:
        List[schemas.Item]: アイテムのリスト。
    """
    items = db.query(models.Item).offset(skip).limit(limit).all()
    return items

# 特定のアイテムを取得
@app.get("/items/{item_id}", response_model=schemas.Item)
def read_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """
    指定されたIDのアイテムを取得します。

    Args:
        item_id (int): アイテムのID。
        db (Session, optional): データベースセッション。
        current_user (schemas.User, optional): 現在のユーザー。

    Raises:
        HTTPException: アイテムが見つからない場合。

    Returns:
        schemas.Item: 取得したアイテム。
    """
    item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

# アイテムの更新エンドポイント
@app.put("/items/{item_id}", response_model=schemas.Item)
def update_item(
    item_id: int,
    item: schemas.ItemCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """
    指定されたIDのアイテムを更新します。

    Args:
        item_id (int): アイテムのID。
        item (schemas.ItemCreate): 更新するアイテムの情報。
        db (Session, optional): データベースセッション。
        current_user (schemas.User, optional): 現在のユーザー。

    Raises:
        HTTPException: アイテムが見つからない場合。

    Returns:
        schemas.Item: 更新されたアイテム。
    """
    db_item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if db_item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    db_item.name = item.name
    db.commit()
    db.refresh(db_item)
    return db_item

# アイテムの削除エンドポイント
@app.delete("/items/{item_id}", response_model=dict)
def delete_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """
    指定されたIDのアイテムを削除します。

    Args:
        item_id (int): 削除するアイテムのID。
        db (Session, optional): データベースセッション。
        current_user (schemas.User, optional): 現在のユーザー。

    Raises:
        HTTPException: アイテムが見つからない場合。

    Returns:
        dict: 削除の結果を示すメッセージ。
    """
    db_item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if db_item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    db.delete(db_item)
    db.commit()
    return {"detail": "Item deleted"}
```
## app/models.py
```app/models.py
from sqlalchemy import Boolean, Column, Integer, String, DateTime, func
from .database import Base

class User(Base):
    """
    ユーザーモデル。ユーザーの基本情報を保持します。
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)  # 管理者フラグを追加

class Item(Base):
    """
    アイテムモデル。アイテムの情報を保持します。
    """
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
```
## app/schemas.py
```app/schemas.py
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

# アイテムの基本モデル（共通項目を定義）
class ItemBase(BaseModel):
    name: str  # アイテムの名前

# アイテム作成時のモデル（追加のプロパティはなし）
class ItemCreate(ItemBase):
    pass  # ItemBaseを継承し、特別な追加項目はない

# アイテム取得時のモデル（IDやタイムスタンプを含む）
class Item(ItemBase):
    id: int  # アイテムの一意のID
    created_at: datetime  # 作成日時
    updated_at: datetime  # 更新日時

    class Config:
        from_attributes = True  # ORM モードを有効にして属性から値を取得できるようにする

# ユーザー作成時のモデル
class UserCreate(BaseModel):
    username: str  # ユーザー名
    password: str  # パスワード

# ユーザー取得時のモデル
class User(BaseModel):
    id: int  # ユーザーの一意のID
    username: str  # ユーザー名
    is_admin: bool  # 管理者権限フラグ

    class Config:
        from_attributes = True  # ORM モードを有効にして属性から値を取得できるようにする

# トークンのモデル（認証用のアクセストークンとそのタイプ）
class Token(BaseModel):
    access_token: str  # JWT アクセストークン
    token_type: str  # トークンのタイプ（例: "bearer"）
    refresh_token: Optional[str] = None
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