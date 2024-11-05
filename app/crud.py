from sqlalchemy.orm import Session
from . import models, schemas, auth

# ユーザー名でユーザーを取得する関数
def get_user_by_username(db: Session, username: str):
    """
    指定されたユーザー名に一致するユーザーをデータベースから取得します。

    Args:
        db (Session): データベースセッション。
        username (str): 検索対象のユーザー名。

    Returns:
        Optional[models.User]: ユーザーが見つかった場合はそのユーザーオブジェクト、見つからない場合はNone。
    """
    return db.query(models.User).filter(models.User.username == username).first()

# 新規ユーザーを作成する関数
def create_user(db: Session, user: schemas.UserCreate, is_admin: bool = False):
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

# アイテム関連の関数を追加
def get_item(db: Session, item_id: int):
    return db.query(models.Item).filter(models.Item.id == item_id).first()

def get_items(db: Session, skip: int = 0, limit: int = 10):
    return db.query(models.Item).offset(skip).limit(limit).all()

def create_item(db: Session, item: schemas.ItemCreate):
    db_item = models.Item(name=item.name)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item

def update_item(db: Session, item_id: int, item: schemas.ItemCreate):
    db_item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if db_item is None:
        return None
    db_item.name = item.name
    db.commit()
    db.refresh(db_item)
    return db_item

def delete_item(db: Session, item_id: int):
    db_item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if db_item is None:
        return None
    db.delete(db_item)
    db.commit()
    return db_item