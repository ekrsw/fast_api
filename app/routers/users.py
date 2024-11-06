from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import schemas, crud
from ..dependencies import get_db

# ユーザー関連のルーター設定
router = APIRouter(
    prefix="/users",
    tags=["users"],
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

# 他のユーザー関連のエンドポイントを追加可能
