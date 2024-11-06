from fastapi import APIRouter, Depends, HTTPException
from typing import List
from sqlalchemy.orm import Session
from .. import schemas, crud, database, auth
from ..dependencies import get_db
from ..auth import get_current_user

# アイテム関連のルーター設定
router = APIRouter(
    prefix="/items",
    tags=["items"],
)

# 新しいアイテムを作成するエンドポイント
@router.post("/", response_model=schemas.Item)
def create_item(
    item: schemas.ItemCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
    ) -> schemas.Item:
    """
    新しいアイテムを作成します。

    Args:
        item (schemas.ItemCreate): 作成するアイテムのデータ。
        db (Session): データベースセッション。
        current_user (schemas.User): 現在の認証されたユーザー。

    Returns:
        schemas.Item: 作成されたアイテムオブジェクト。
    """
    return crud.create_item(db=db, item=item)

# 複数のアイテムを取得するエンドポイント
@router.get("/", response_model=List[schemas.Item])
def read_items(
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
    ) -> List[schemas.Item]:
    """
    アイテムのリストを取得します。

    Args:
        skip (int, optional): 取得をスキップするアイテムの数。デフォルトは0。
        limit (int, optional): 取得するアイテムの上限数。デフォルトは10。
        db (Session): データベースセッション。
        current_user (schemas.User): 現在の認証されたユーザー。

    Returns:
        List[schemas.Item]: アイテムのリスト。
    """
    return crud.get_items(db, skip=skip, limit=limit)

# 特定のIDのアイテムを取得するエンドポイント
@router.get("/{item_id}", response_model=schemas.Item)
def read_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
    ) -> schemas.Item:
    """
    指定されたIDのアイテムを取得します。

    Args:
        item_id (int): 取得対象のアイテムID。
        db (Session): データベースセッション。
        current_user (schemas.User): 現在の認証されたユーザー。

    Returns:
        schemas.Item: 指定されたアイテムオブジェクト。見つからない場合は404エラー。
    """
    db_item = crud.get_item(db, item_id=item_id)
    if db_item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return db_item

# 特定のIDのアイテムを更新するエンドポイント
@router.put("/{item_id}", response_model=schemas.Item)
def update_item(
    item_id: int,
    item: schemas.ItemCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
    ) -> schemas.Item:
    """
    指定されたIDのアイテムを更新します。

    Args:
        item_id (int): 更新対象のアイテムID。
        item (schemas.ItemCreate): 新しいアイテムデータ。
        db (Session): データベースセッション。
        current_user (schemas.User): 現在の認証されたユーザー。

    Returns:
        schemas.Item: 更新されたアイテムオブジェクト。
    """
    return crud.update_item(db=db, item_id=item_id, item=item)

# 特定のIDのアイテムを削除するエンドポイント
@router.delete("/{item_id}", response_model=dict)
def delete_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
    ) -> dict:
    """
    指定されたIDのアイテムを削除します。

    Args:
        item_id (int): 削除対象のアイテムID。
        db (Session): データベースセッション。
        current_user (schemas.User): 現在の認証されたユーザー。

    Returns:
        dict: 削除完了メッセージを含む辞書オブジェクト。
    """
    crud.delete_item(db=db, item_id=item_id)
    return {"detail": "Item deleted"}
