from sqlalchemy import Boolean, Column, Integer, String
from .database import BaseDatabase


class User(BaseDatabase):
    """
    ユーザーモデル。ユーザーの基本情報を保持します。

    Attributes
    ----------
    id : sqlalchemy.Column
        ユーザーの一意な識別子。プライマリキーであり、インデックスが作成されています。
    username : sqlalchemy.Column
        ユーザー名。ユニークであり、インデックスが作成されています。必須項目です。
    hashed_password : sqlalchemy.Column
        ユーザーのハッシュ化されたパスワード。必須項目です。
    is_admin : sqlalchemy.Column
        ユーザーが管理者かどうかを示すフラグ。デフォルトはFalseです。
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)  # 管理者フラグ


class Item(BaseDatabase):
    """
    アイテムモデル。アイテムの情報を保持します。

    Attributes
    ----------
    id : sqlalchemy.Column
        アイテムの一意な識別子。プライマリキーであり、インデックスが作成されています。
    name : sqlalchemy.Column
        アイテムの名前。インデックスが作成されており、必須項目です。
    """
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
