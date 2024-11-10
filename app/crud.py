from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update, delete
from . import models, schemas, auth
from typing import Optional, List


# ユーザー名でユーザーを取得する関数
async def get_user_by_username(db: AsyncSession, username: str) -> Optional[models.User]:
    """
    ユーザー名でユーザーを取得します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    username : str
        取得するユーザーのユーザー名。

    Returns
    -------
    Optional[models.User]
        見つかった場合はユーザーオブジェクト、存在しない場合はNone。
    """
    result = await db.execute(select(models.User).filter(models.User.username == username))
    return result.scalars().first()

# 全ユーザーを取得する関数
async def get_users(db: AsyncSession, skip: int = 0, limit: int = 100) -> List[models.User]:
    """
    ユーザーのリストを取得します（ページング可能）。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    skip : int, optional
        取得をスキップするレコード数（デフォルトは0）。
    limit : int, optional
        取得する最大レコード数（デフォルトは100）。

    Returns
    -------
    List[models.User]
        ユーザーオブジェクトのリスト。
    """
    result = await db.execute(select(models.User).offset(skip).limit(limit))
    return result.scalars().all()

# 新規ユーザーを作成する関数
async def create_user(db: AsyncSession, user: schemas.UserCreate, is_admin: bool = False) -> models.User:
    """
    新しいユーザーを作成します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    user : schemas.UserCreate
        新規ユーザーの情報を含むスキーマ。
    is_admin : bool, optional
        ユーザーに管理者権限を付与するか（デフォルトはFalse）。

    Returns
    -------
    models.User
        作成された新しいユーザーオブジェクト。
    """
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password, is_admin=is_admin)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

# ユーザー情報を更新する関数
async def update_user(db: AsyncSession, username: str, user_update: schemas.UserUpdate) -> Optional[models.User]:
    """
    ユーザー情報を更新します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    username : str
        更新対象のユーザー名。
    user_update : schemas.UserUpdate
        更新するユーザー情報を含むスキーマ。

    Returns
    -------
    Optional[models.User]
        更新されたユーザーオブジェクト。ユーザーが存在しない場合はNone。
    """
    result = await db.execute(select(models.User).filter(models.User.username == username))
    db_user = result.scalars().first()
    if db_user is None:
        return None
    
    if user_update.username:
        db_user.username = user_update.username
    if user_update.password:
        db_user.hashed_password = auth.get_password_hash(user_update.password)
    if user_update.is_admin is not None:
        db_user.is_admin = user_update.is_admin
    
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

# ユーザーを削除する関数
async def delete_user(db: AsyncSession, username: str) -> Optional[models.User]:
    """
    ユーザーを削除します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    username : str
        削除対象のユーザー名。

    Returns
    -------
    Optional[models.User]
        削除されたユーザーオブジェクト。存在しない場合はNone。
    """
    result = await db.execute(select(models.User).filter(models.User.username == username))
    db_user = result.scalars().first()
    if db_user is None:
        return None

    await db.delete(db_user)
    await db.commit()
    return db_user


# アイテムIDで特定のアイテムを取得する関数
async def get_item(db: AsyncSession, item_id: int) -> Optional[models.Item]:
    """
    アイテムIDで特定のアイテムを取得します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    item_id : int
        取得するアイテムのID。

    Returns
    -------
    Optional[models.Item]
        見つかった場合はアイテムオブジェクト、存在しない場合はNone。
    """
    result = await db.execute(select(models.Item).filter(models.Item.id == item_id))
    return result.scalars().first()

# 複数のアイテムを取得する関数
async def get_items(db: AsyncSession, skip: int = 0, limit: int = 10) -> List[models.Item]:
    """
    アイテムのリストを取得します（ページング可能）。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    skip : int, optional
        取得をスキップするレコード数（デフォルトは0）。
    limit : int, optional
        取得する最大レコード数（デフォルトは10）。

    Returns
    -------
    List[models.Item]
        アイテムオブジェクトのリスト。
    """
    result = await db.execute(select(models.Item).offset(skip).limit(limit))
    return result.scalars().all()

# 新しいアイテムを作成する関数
async def create_item(db: AsyncSession, item: schemas.ItemCreate) -> models.Item:
    """
    新しいアイテムを作成します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    item : schemas.ItemCreate
        新規アイテムの情報を含むスキーマ。

    Returns
    -------
    models.Item
        作成された新しいアイテムオブジェクト。
    """
    db_item = models.Item(name=item.name)
    db.add(db_item)
    await db.commit()
    await db.refresh(db_item)
    return db_item

# アイテムを更新する関数
async def update_item(db: AsyncSession, item_id: int, item: schemas.ItemCreate) -> Optional[models.Item]:
    """
    アイテムIDでアイテムを更新します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    item_id : int
        更新するアイテムのID。
    item : schemas.ItemCreate
        更新するアイテム情報を含むスキーマ。

    Returns
    -------
    Optional[models.Item]
        更新されたアイテムオブジェクト。アイテムが存在しない場合はNone。
    """
    result = await db.execute(select(models.Item).filter(models.Item.id == item_id))
    db_item = result.scalars().first()
    if db_item is None:
        return None
    db_item.name = item.name
    await db.commit()
    await db.refresh(db_item)
    return db_item

# アイテムを削除する関数
async def delete_item(db: AsyncSession, item_id: int) -> Optional[models.Item]:
    """
    アイテムIDでアイテムを削除します。

    Parameters
    ----------
    db : AsyncSession
        データベースセッション。
    item_id : int
        削除するアイテムのID。

    Returns
    -------
    Optional[models.Item]
        削除されたアイテムオブジェクト。アイテムが存在しない場合はNone。
    """
    result = await db.execute(select(models.Item).filter(models.Item.id == item_id))
    db_item = result.scalars().first()
    if db_item is None:
        return None
    await db.delete(db_item)
    await db.commit()
    return db_item
