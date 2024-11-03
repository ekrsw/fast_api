from sqlalchemy import Boolean, Column, Integer, String, DateTime, func
from .database import Base

class User(Base):
    """
    ユーザーモデル。ユーザーの基本情報を保持します。
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False)  # 管理者フラグを追加

class Item(Base):
    """
    アイテムモデル。アイテムの情報を保持します。
    """
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
