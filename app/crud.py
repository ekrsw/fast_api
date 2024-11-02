from sqlalchemy.orm import Session
from . import models, schemas, auth

# ユーザー名でユーザーを取得する関数
def get_user_by_username(db: Session, username: str):
    """
    指定されたユーザー名に一致するユーザーをデータベースから取得します。
    
    args:
    - db: データベースセッション
    - username: 検索対象のユーザー名

    return:
    - ユーザーが見つかった場合はそのユーザーオブジェクト、見つからない場合はNone
    """
    return db.query(models.User).filter(models.User.username == username).first()

def create_user(db: Session, user: schemas.UserCreate, is_admin: bool = False):
    """
    新しいユーザーをデータベースに作成します。パスワードはハッシュ化されます。
    
    args:
    - db: データベースセッション
    - user: 作成するユーザーのデータを含むUserCreateスキーマ
    - is_admin: ユーザーが管理者かどうかを示すブール値（デフォルトはFalse）

    return:
    - 作成されたユーザーオブジェクト
    """
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password, is_admin=is_admin)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
