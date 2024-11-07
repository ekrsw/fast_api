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