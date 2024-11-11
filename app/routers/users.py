from fastapi import APIRouter, Depends, HTTPException, status
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
    認証不要でアクセスできます。

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
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
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

@router.post("/add", response_model=schemas.User)
async def add_user(
        user: schemas.UserCreate,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
    ) -> schemas.User:
    """
    管理者が新しいユーザーを追加します。
    
    このエンドポイントは、認証された管理者ユーザーのみがアクセスできます。
    提供されたユーザー情報を基に新しいユーザーをデータベースに作成します。
    
    Parameters
    ----------
    user : schemas.UserCreate
        作成するユーザーの情報を含むスキーマ。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : auth_schemas.User
        現在認証されているユーザー。依存関係として提供されます。
    
    Returns
    -------
    schemas.User
        作成されたユーザーの詳細を含むレスポンスモデル。
    
    Raises
    ------
    HTTPException
        認証されたユーザーが管理者でない場合に403 Forbiddenエラーを返します。
        ユーザー名が既に登録されている場合に400 Bad Requestエラーを返します。
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to add users")
    
    db_user = await crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    return await crud.create_user(db=db, user=user)

@router.put("/{username}", response_model=schemas.User)
async def update_user_info(
        username: str,
        user_update: schemas.UserUpdate,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
    ) -> schemas.User:
    """
    ユーザー情報を更新します。
    
    このエンドポイントは、認証されたユーザー自身または管理者のみがアクセスできます。
    提供されたユーザー情報を基に指定されたユーザーを更新します。
    
    Parameters
    ----------
    username : str
        更新対象のユーザー名。
    user_update : schemas.UserUpdate
        更新するユーザー情報を含むスキーマ。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : auth_schemas.User
        現在認証されているユーザー。依存関係として提供されます。
    
    Returns
    -------
    schemas.User
        更新されたユーザーの詳細を含むレスポンスモデル。
    
    Raises
    ------
    HTTPException
        認証されたユーザーが対象ユーザー自身でないか、管理者でない場合に403 Forbiddenエラーを返します。
        ユーザーが存在しない場合に404 Not Foundエラーを返します。
    """
    if current_user.username != username and not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to update this user")
    
    updated_user = await crud.update_user(db, username=username, user_update=user_update)
    if updated_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return updated_user

@router.delete("/{username}", response_model=dict)
async def delete_user(
        username: str,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
    ) -> dict:
    """
    ユーザーを削除します（管理者のみ）。

    このエンドポイントは、指定されたユーザー名のユーザーを削除します。
    認証された管理者ユーザーのみがアクセスできます。

    Parameters
    ----------
    username : str
        削除対象のユーザー名。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : schemas.User
        現在認証されているユーザー。依存関係として提供されます。

    Returns
    -------
    dict
        削除の詳細を含むレスポンス。例: {"detail": "User 'username' deleted"}

    Raises
    ------
    HTTPException
        認証されたユーザーが管理者でない場合に403 Forbiddenエラーを返します。
        ユーザーが存在しない場合に404 Not Foundエラーを返します。
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete users")

    deleted_user = await crud.delete_user(db, username=username)
    if deleted_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return {"detail": f"User '{username}' deleted"}