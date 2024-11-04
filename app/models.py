from sqlalchemy import Boolean, Column, Integer, String
from .database import BaseDatabase

class User(BaseDatabase):
    """
    ユーザーモデル。ユーザーの基本情報を保持します。
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)  # 管理者フラグ

class Item(BaseDatabase):
    """
    アイテムモデル。アイテムの情報を保持します。
    """
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)