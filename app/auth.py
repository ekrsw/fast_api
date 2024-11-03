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
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY")
REFRESH_TOKEN_EXPIRE_MINUTES = int(os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES", 1440))

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

# リフレッシュトークンを作成する関数
def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    リフレッシュトークンを作成して返します。

    Args:
        data (dict): トークンに含めるデータ。
        expires_delta (Optional[timedelta]): トークンの有効期限。

    Returns:
        str: 作成されたリフレッシュトークン。
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
        to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, REFRESH_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt