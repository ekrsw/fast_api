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
