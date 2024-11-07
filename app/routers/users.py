from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from .. import schemas, crud
from ..dependencies import get_db
from ..auth import get_current_user

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(get_current_user)],
    responses={404: {"description": "Not found"}},
)


@router.post("/", response_model=schemas.User)
async def register_user(
        user: schemas.UserCreate,
        db: AsyncSession = Depends(get_db)
        ) -> schemas.User:
    """
    新しいユーザーを登録します。
    
    このエンドポイントは、提供されたユーザー情報を基に新しいユーザーをデータベースに作成します。
    ユーザー名が既に登録されている場合はエラーを返します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    user : schemas.UserCreate
        作成するユーザーの情報を含むスキーマ。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。

    Returns
    -------
    schemas.User
        作成されたユーザーの詳細を含むレスポンスモデル。

    Raises
    ------
    HTTPException
        ユーザー名が既に登録されている場合に400 Bad Requestエラーを返します。
    """
    # ユーザー名で既存のユーザーを取得
    db_user = await crud.get_user_by_username(db, username=user.username)
    if db_user:
        # ユーザー名が既に存在する場合はエラーを返す
        raise HTTPException(status_code=400, detail="Username already registered")
    # 新しいユーザーを作成して返す
    return await crud.create_user(db=db, user=user)


@router.get("/{username}", response_model=schemas.User)
async def read_user(
        username: str,
        db: AsyncSession = Depends(get_db)
        ) -> schemas.User:
    """
    特定のユーザーを取得します。
    
    このエンドポイントは、指定されたユーザー名に基づいてユーザーをデータベースから取得します。
    ユーザーが存在しない場合は404エラーを返します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    username : str
        取得対象のユーザー名。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。

    Returns
    -------
    schemas.User
        取得したユーザーの詳細を含むレスポンスモデル。

    Raises
    ------
    HTTPException
        ユーザーが存在しない場合に404 Not Foundエラーを返します。
    """
    # ユーザー名でユーザーを取得
    db_user = await crud.get_user_by_username(db, username=username)
    if db_user is None:
        # ユーザーが存在しない場合は404エラーを返す
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.get("/", response_model=List[schemas.User])
async def read_users(
        skip: int = 0,
        limit: int = 100,
        db: AsyncSession = Depends(get_db)
        ) -> List[schemas.User]:
    """
    複数のユーザーを取得します。
    
    このエンドポイントは、指定された範囲内でユーザーのリストをデータベースから取得します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    skip : int, optional
        スキップするレコード数。デフォルトは0。
    limit : int, optional
        取得するレコード数の上限。デフォルトは100。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。

    Returns
    -------
    List[schemas.User]
        取得したユーザーのリスト。
    """
    # 指定された範囲でユーザーを取得して返す
    users = await crud.get_users(db, skip=skip, limit=limit)
    return users
