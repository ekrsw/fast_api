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
