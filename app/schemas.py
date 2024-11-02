from pydantic import BaseModel
from datetime import datetime

# アイテムの基本モデル（共通項目を定義）
class ItemBase(BaseModel):
    name: str  # アイテムの名前

# アイテム作成時のモデル（追加のプロパティはなし）
class ItemCreate(ItemBase):
    pass  # ItemBaseを継承し、特別な追加項目はない

# アイテム取得時のモデル（IDやタイムスタンプを含む）
class Item(ItemBase):
    id: int  # アイテムの一意のID
    created_at: datetime  # 作成日時
    updated_at: datetime  # 更新日時

    class Config:
        from_attributes = True  # ORM モードを有効にして属性から値を取得できるようにする

# ユーザー作成時のモデル
class UserCreate(BaseModel):
    username: str  # ユーザー名
    password: str  # パスワード

# ユーザー取得時のモデル
class User(BaseModel):
    id: int  # ユーザーの一意のID
    username: str  # ユーザー名
    is_admin: bool  # 管理者権限フラグ

    class Config:
        from_attributes = True  # ORM モードを有効にして属性から値を取得できるようにする

# トークンのモデル（認証用のアクセストークンとそのタイプ）
class Token(BaseModel):
    access_token: str  # JWT アクセストークン
    token_type: str  # トークンのタイプ（例: "bearer"）
