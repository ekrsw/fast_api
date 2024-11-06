from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from . import schemas, crud
from .dependencies import get_db

# .env ファイルの読み込み
load_dotenv()

# パスワードハッシュの設定
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT 設定
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY")
REFRESH_ALGORITHM = os.getenv("REFRESH_ALGORITHM", "HS256")
REFRESH_TOKEN_EXPIRE_MINUTES = int(os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES", 1440))

# OAuth2 パスワード認証を設定
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

# パスワードを検証する関数
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

# パスワードをハッシュ化する関数
def get_password_hash(password: str) -> str:
    """
    パスワードをハッシュ化して保存用に変換します。

    Args:
        password (str): 平文のパスワード。

    Returns:
        str: ハッシュ化されたパスワード。
    """
    return pwd_context.hash(password)

# アクセストークンを作成する関数
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    アクセストークンを作成し、JWT形式でエンコードします。

    Args:
        data (dict): トークンに含めるペイロードデータ。
        expires_delta (Optional[timedelta]): トークンの有効期限。

    Returns:
        str: JWT形式のアクセストークン。
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# リフレッシュトークンを作成する関数
def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    リフレッシュトークンを作成し、JWT形式でエンコードします。

    Args:
        data (dict): トークンに含めるペイロードデータ。
        expires_delta (Optional[timedelta]): トークンの有効期限。

    Returns:
        str: JWT形式のリフレッシュトークン。
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(days=1))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=REFRESH_ALGORITHM)

# トークンをデコードする関数
def decode_token(token: str, secret_key: str, algorithms: list) -> dict:
    """
    トークンをデコードし、含まれるペイロードデータを取得します。

    Args:
        token (str): デコードするトークン。
        secret_key (str): デコードに使用する秘密鍵。
        algorithms (list): トークンのデコードに使用するアルゴリズム。

    Returns:
        dict: トークンに含まれるペイロードデータ。
    """
    return jwt.decode(token, secret_key, algorithms=algorithms)

# ユーザー認証の関数
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
        return False
    return user

# 現在のユーザーの取得
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> schemas.User:
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
        payload = decode_token(token, SECRET_KEY, [ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception
    return user

# リフレッシュトークンの取得（ヘッダーから取得）
def get_refresh_token(refresh_token: str = Header(...)) -> str:
    """
    リフレッシュトークンをヘッダーから取得します。

    Args:
        refresh_token (str): ヘッダーから取得したリフレッシュトークン。

    Returns:
        str: リフレッシュトークン。
    """
    return refresh_token

# JWT エラークラスのラッピング
class JWTError(Exception):
    """
    JWT関連のエラーを扱うための例外クラス。
    """
    pass
