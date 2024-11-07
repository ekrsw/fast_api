# auth.py

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
