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
