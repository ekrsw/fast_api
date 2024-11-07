from fastapi import APIRouter, Depends, HTTPException
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from .. import schemas, crud
from ..dependencies import get_db
from ..auth import get_current_user

router = APIRouter(
    prefix="/items",
    tags=["items"],
)


@router.post("/", response_model=schemas.Item)
async def create_item(
        item: schemas.ItemCreate,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
        ) -> schemas.Item:
    """
    新しいアイテムを作成します。

    このエンドポイントは、提供されたアイテム情報を基に新しいアイテムをデータベースに作成します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    item : schemas.ItemCreate
        作成するアイテムの情報を含むスキーマ。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : schemas.User
        現在認証されているユーザー。依存関係として提供されます。

    Returns
    -------
    schemas.Item
        作成されたアイテムの詳細を含むレスポンスモデル。
    """
    # 新しいアイテムを作成して返す
    return await crud.create_item(db=db, item=item)


@router.get("/", response_model=List[schemas.Item])
async def read_items(
        skip: int = 0,
        limit: int = 10,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
        ) -> List[schemas.Item]:
    """
    複数のアイテムを取得します。

    このエンドポイントは、指定された範囲内でアイテムのリストをデータベースから取得します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    skip : int, optional
        スキップするレコード数。デフォルトは0。
    limit : int, optional
        取得するレコード数の上限。デフォルトは10。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : schemas.User
        現在認証されているユーザー。依存関係として提供されます。

    Returns
    -------
    List[schemas.Item]
        取得したアイテムのリスト。
    """
    # 指定された範囲でアイテムを取得して返す
    return await crud.get_items(db, skip=skip, limit=limit)


@router.get("/{item_id}", response_model=schemas.Item)
async def read_item(
        item_id: int,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
        ) -> schemas.Item:
    """
    特定のアイテムを取得します。

    このエンドポイントは、指定されたアイテムIDに基づいてアイテムをデータベースから取得します。
    アイテムが存在しない場合は404エラーを返します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    item_id : int
        取得対象のアイテムID。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : schemas.User
        現在認証されているユーザー。依存関係として提供されます。

    Returns
    -------
    schemas.Item
        取得したアイテムの詳細を含むレスポンスモデル。

    Raises
    ------
    HTTPException
        アイテムが存在しない場合に404 Not Foundエラーを返します。
    """
    # アイテムをデータベースから取得
    db_item = await crud.get_item(db, item_id=item_id)
    if db_item is None:
        # アイテムが存在しない場合は404エラーを返す
        raise HTTPException(status_code=404, detail="Item not found")
    return db_item


@router.put("/{item_id}", response_model=schemas.Item)
async def update_item(
        item_id: int,
        item: schemas.ItemCreate,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
        ) -> schemas.Item:
    """
    特定のアイテムを更新します。

    このエンドポイントは、指定されたアイテムIDに基づいてアイテムをデータベース内で更新します。
    アイテムが存在しない場合は404エラーを返します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    item_id : int
        更新対象のアイテムID。
    item : schemas.ItemCreate
        更新後のアイテム情報を含むスキーマ。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : schemas.User
        現在認証されているユーザー。依存関係として提供されます。

    Returns
    -------
    schemas.Item
        更新されたアイテムの詳細を含むレスポンスモデル。

    Raises
    ------
    HTTPException
        アイテムが存在しない場合に404 Not Foundエラーを返します。
    """
    # アイテムをデータベースで更新
    updated_item = await crud.update_item(db=db, item_id=item_id, item=item)
    if updated_item is None:
        # アイテムが存在しない場合は404エラーを返す
        raise HTTPException(status_code=404, detail="Item not found")
    return updated_item


@router.delete("/{item_id}", response_model=dict)
async def delete_item(
        item_id: int,
        db: AsyncSession = Depends(get_db),
        current_user: schemas.User = Depends(get_current_user)
        ) -> dict:
    """
    特定のアイテムを削除します。

    このエンドポイントは、指定されたアイテムIDに基づいてアイテムをデータベースから削除します。
    アイテムが存在しない場合は404エラーを返します。
    認証されたユーザーのみがアクセスできます。

    Parameters
    ----------
    item_id : int
        削除対象のアイテムID。
    db : AsyncSession
        データベースセッション。依存関係として提供されます。
    current_user : schemas.User
        現在認証されているユーザー。依存関係として提供されます。

    Returns
    -------
    dict
        削除の詳細を含むレスポンス。例: {"detail": "Item deleted"}

    Raises
    ------
    HTTPException
        アイテムが存在しない場合に404 Not Foundエラーを返します。
    """
    # アイテムをデータベースから削除
    deleted_item = await crud.delete_item(db=db, item_id=item_id)
    if deleted_item is None:
        # アイテムが存在しない場合は404エラーを返す
        raise HTTPException(status_code=404, detail="Item not found")
    return {"detail": "Item deleted"}
