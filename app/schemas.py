from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class ItemBase(BaseModel):
    """
    アイテムの基本モデル（共通項目を定義）
    """
    name: str  # アイテムの名前

class ItemCreate(ItemBase):
    """
    アイテム作成時のモデル（追加のプロパティはなし）
    """
    pass  # ItemBaseを継承し、特別な追加項目はない

class Item(ItemBase):
    """
    アイテム取得時のモデル（IDやタイムスタンプを含む）
    """
    id: int  # アイテムの一意のID
    created_at: datetime  # 作成日時
    updated_at: datetime  # 更新日時

    class Config:
        from_attributes = True  # ORM モードを有効にして属性から値を取得できるようにする

class UserCreate(BaseModel):
    """
    ユーザー作成時のモデル
    """
    username: str  # ユーザー名
    password: str  # パスワード

class User(BaseModel):
    """
    ユーザー取得時のモデル
    """
    id: int  # ユーザーの一意のID
    username: str  # ユーザー名
    is_admin: bool  # 管理者権限フラグ

    class Config:
        from_attributes = True  # ORM モードを有効にして属性から値を取得できるようにする

class Token(BaseModel):
    """
    トークンのモデル（認証用のアクセストークンとリフレッシュトークン）
    """
    access_token: str  # JWT アクセストークン
    token_type: str  # トークンのタイプ（例: "bearer"）
    refresh_token: Optional[str] = None  # JWT リフレッシュトークン