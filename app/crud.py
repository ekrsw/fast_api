from sqlalchemy.orm import Session
from . import models, schemas, auth
from typing import Optional, List

# ユーザー名でユーザーを取得する関数
def get_user_by_username(db: Session, username: str) -> Optional[models.User]:
    """
    指定されたユーザー名に一致するユーザーをデータベースから取得します。

    Args:
        db (Session): データベースセッション。
        username (str): 検索対象のユーザー名。

    Returns:
        Optional[models.User]: ユーザーが見つかった場合はそのユーザーオブジェクト、見つからない場合はNone。
    """
    return db.query(models.User).filter(models.User.username == username).first()

# 全ユーザーを取得する関数
def get_users(db: Session, skip: int = 0, limit: int = 100) -> List[models.User]:
    """
    全てのユーザーを取得します。

    Args:
        db (Session): データベースセッション。
        skip (int, optional): スキップするユーザー数。デフォルトは0。
        limit (int, optional): 取得するユーザー数の上限。デフォルトは100。

    Returns:
        List[models.User]: ユーザーのリスト。
    """
    return db.query(models.User).offset(skip).limit(limit).all()

# 新規ユーザーを作成する関数
def create_user(db: Session, user: schemas.UserCreate, is_admin: bool = False) -> models.User:
    """
    新しいユーザーをデータベースに作成します。パスワードはハッシュ化されます。

    Args:
        db (Session): データベースセッション。
        user (schemas.UserCreate): 作成するユーザーのデータを含むUserCreateスキーマ。
        is_admin (bool, optional): ユーザーが管理者かどうかを示すブール値。デフォルトはFalse。

    Returns:
        models.User: 作成されたユーザーオブジェクト。
    """
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password, is_admin=is_admin)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# アイテムIDで特定のアイテムを取得する関数
def get_item(db: Session, item_id: int) -> Optional[models.Item]:
    """
    指定されたIDに一致するアイテムをデータベースから取得します。

    Args:
        db (Session): データベースセッション。
        item_id (int): 検索対象のアイテムID。

    Returns:
        Optional[models.Item]: アイテムが見つかった場合はそのアイテムオブジェクト、見つからない場合はNone。
    """
    return db.query(models.Item).filter(models.Item.id == item_id).first()

# 複数のアイテムを取得する関数
def get_items(db: Session, skip: int = 0, limit: int = 10) -> List[models.Item]:
    """
    指定されたオフセットと制限で、データベースから複数のアイテムを取得します。

    Args:
        db (Session): データベースセッション。
        skip (int, optional): スキップするアイテム数。デフォルトは0。
        limit (int, optional): 取得するアイテム数の制限。デフォルトは10。

    Returns:
        List[models.Item]: アイテムのリスト。
    """
    return db.query(models.Item).offset(skip).limit(limit).all()

# 新しいアイテムを作成する関数
def create_item(db: Session, item: schemas.ItemCreate) -> models.Item:
    """
    新しいアイテムをデータベースに作成します。

    Args:
        db (Session): データベースセッション。
        item (schemas.ItemCreate): 作成するアイテムのデータを含むItemCreateスキーマ。

    Returns:
        models.Item: 作成されたアイテムオブジェクト。
    """
    db_item = models.Item(name=item.name)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item

# アイテムを更新する関数
def update_item(db: Session, item_id: int, item: schemas.ItemCreate) -> Optional[models.Item]:
    """
    指定されたIDのアイテムを更新します。

    Args:
        db (Session): データベースセッション。
        item_id (int): 更新対象のアイテムID。
        item (schemas.ItemCreate): 新しいアイテムデータを含むItemCreateスキーマ。

    Returns:
        Optional[models.Item]: 更新されたアイテムオブジェクト。アイテムが見つからない場合はNone。
    """
    db_item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if db_item is None:
        return None
    db_item.name = item.name
    db.commit()
    db.refresh(db_item)
    return db_item

# アイテムを削除する関数
def delete_item(db: Session, item_id: int) -> Optional[models.Item]:
    """
    指定されたIDのアイテムをデータベースから削除します。

    Args:
        db (Session): データベースセッション。
        item_id (int): 削除対象のアイテムID。

    Returns:
        Optional[models.Item]: 削除されたアイテムオブジェクト。アイテムが見つからない場合はNone。
    """
    db_item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if db_item is None:
        return None
    db.delete(db_item)
    db.commit()
    return db_item
