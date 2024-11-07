# auth_router.py

from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from .. import schemas, crud, auth
from ..dependencies import get_db
from ..config import settings
import logging

# ロガーの設定
logger = logging.getLogger(__name__)

# 認証用のルーターを設定
router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


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
    logger.info(f"ユーザー '{form_data.username}' のログイン試行中。")
    # ユーザーの認証
    user = auth.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        logger.warning(f"認証失敗: ユーザー '{form_data.username}' の資格情報が不正です。")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ユーザー名またはパスワードが正しくありません。",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # アクセストークンの有効期限を設定
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = auth.create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )
    
    # リフレッシュトークンの有効期限を設定
    refresh_token_expires = timedelta(minutes=settings.refresh_token_expire_minutes)
    refresh_token = auth.create_refresh_token(
        data={"sub": user.username},
        expires_delta=refresh_token_expires
    )
    
    logger.info(f"ユーザー '{form_data.username}' のトークン発行成功。")
    
    # トークンを返す
    return schemas.Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=refresh_token
    )


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
    logger.info("リフレッシュトークンを使用してアクセストークンの更新を試行中。")
    try:
        # リフレッシュトークンをデコードしてユーザー名を取得
        payload = auth.decode_token(
            token=refresh_token,
            secret_key=settings.refresh_secret_key,
            algorithms=[settings.refresh_algorithm]
        )
        username: Optional[str] = payload.get("sub")
        if username is None:
            logger.warning("リフレッシュトークンにユーザー名が含まれていません。")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="無効なトークンです。")
    except JWTError:
        logger.error("リフレッシュトークンのデコードに失敗しました。")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="無効なトークンです。")
    
    # ユーザーが存在するかを確認
    user = crud.get_user_by_username(db, username=username)
    if user is None:
        logger.warning(f"リフレッシュトークンに対応するユーザー '{username}' が見つかりません。")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ユーザーが見つかりません。")
    
    # 新しいアクセストークンの有効期限を設定
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = auth.create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )
    
    logger.info(f"ユーザー '{username}' のアクセストークンを更新しました。")
    
    # 新しいアクセストークンを返す
    return schemas.Token(
        access_token=access_token,
        token_type="bearer",
        refresh_token=refresh_token  # 必要に応じてリフレッシュトークンも返す場合
    )
