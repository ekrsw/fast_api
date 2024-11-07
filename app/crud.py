from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import update, delete
from . import models, schemas, auth
from typing import Optional, List

# ユーザー名でユーザーを取得する関数
async def get_user_by_username(db: AsyncSession, username: str) -> Optional[models.User]:
    result = await db.execute(select(models.User).filter(models.User.username == username))
    return result.scalars().first()

# 全ユーザーを取得する関数
async def get_users(db: AsyncSession, skip: int = 0, limit: int = 100) -> List[models.User]:
    result = await db.execute(select(models.User).offset(skip).limit(limit))
    return result.scalars().all()

# 新規ユーザーを作成する関数
async def create_user(db: AsyncSession, user: schemas.UserCreate, is_admin: bool = False) -> models.User:
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password, is_admin=is_admin)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

# アイテムIDで特定のアイテムを取得する関数
async def get_item(db: AsyncSession, item_id: int) -> Optional[models.Item]:
    result = await db.execute(select(models.Item).filter(models.Item.id == item_id))
    return result.scalars().first()

# 複数のアイテムを取得する関数
async def get_items(db: AsyncSession, skip: int = 0, limit: int = 10) -> List[models.Item]:
    result = await db.execute(select(models.Item).offset(skip).limit(limit))
    return result.scalars().all()

# 新しいアイテムを作成する関数
async def create_item(db: AsyncSession, item: schemas.ItemCreate) -> models.Item:
    db_item = models.Item(name=item.name)
    db.add(db_item)
    await db.commit()
    await db.refresh(db_item)
    return db_item

# アイテムを更新する関数
async def update_item(db: AsyncSession, item_id: int, item: schemas.ItemCreate) -> Optional[models.Item]:
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
    result = await db.execute(select(models.Item).filter(models.Item.id == item_id))
    db_item = result.scalars().first()
    if db_item is None:
        return None
    await db.delete(db_item)
    await db.commit()
    return db_item
