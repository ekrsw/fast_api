from pydantic import BaseModel, ConfigDict, constr, Field, field_validator
from datetime import datetime
from typing import Optional


class ItemBase(BaseModel):
    """
    アイテムの基本モデル（共通項目を定義）

    Attributes
    ----------
    name : str
        アイテムの名前。
    """
    
    name: constr(min_length=1)  # 空文字を禁止
    class Config:
        from_attributes = True

class ItemCreate(ItemBase):
    """
    アイテム作成時のモデル（追加のプロパティはなし）

    このクラスは `ItemBase` を継承しており、アイテム作成時に必要な基本項目を提供します。
    特別な追加項目はありません。
    """
    pass  # ItemBaseを継承し、特別な追加項目はない


class Item(ItemBase):
    """
    アイテム取得時のモデル（IDやタイムスタンプを含む）

    Attributes
    ----------
    id : int
        アイテムの一意のID。
    created_at : datetime
        アイテムが作成された日時。
    updated_at : datetime
        アイテムが最後に更新された日時。
    """
    id: int  # アイテムの一意のID
    created_at: datetime  # 作成日時
    updated_at: datetime  # 更新日時

    class Config:
        from_attributes = True  # ORM モードを有効にして属性から値を取得できるようにする


class UserCreate(BaseModel):
    """
    ユーザー作成時のモデル

    Attributes
    ----------
    username : str
        ユーザー名。3文字以上、50文字以下
    password : str
        パスワード。6文字以上
    """
    username: constr(min_length=3, max_length=50)
    password: constr(min_length=6)


class User(BaseModel):
    """
    ユーザー取得時のモデル

    Attributes
    ----------
    id : int
        ユーザーの一意のID。
    username : str
        ユーザー名。
    is_admin : bool
        管理者権限フラグ。
    """
    id: int  # ユーザーの一意のID
    username: str  # ユーザー名
    is_admin: bool  # 管理者権限フラグ

    class Config:
        from_attributes = True  # ORM モードを有効にして属性から値を取得できるようにする


class UserUpdate(BaseModel):
    """
    ユーザー更新時のモデル
    
    Attributes
    ----------
    username : Optional[str]
        更新後のユーザー名。省略可能。
    password : Optional[str]
        更新後のパスワード。省略可能。
    is_admin : Optional[bool]
        管理者権限フラグ。省略可能。
    """
    username: Optional[constr(min_length=3, max_length=50)] = None
    password: Optional[constr(min_length=6)] = None
    is_admin: Optional[bool] = None

    @field_validator('username')
    def username_must_not_be_empty(cls, v):
        if v is not None and not v.strip():
            raise ValueError('Username must not be empty')
        return v

    @field_validator('password')
    def password_must_not_be_empty(cls, v):
        if v is not None and not v.strip():
            raise ValueError('Password must not be empty')
        return v

    model_config = ConfigDict()


class Token(BaseModel):
    """
    トークンのモデル（認証用のアクセストークンとリフレッシュトークン）

    Attributes
    ----------
    access_token : str
        JWT アクセストークン。
    token_type : str
        トークンのタイプ（例: "bearer"）。
    refresh_token : Optional[str]
        JWT リフレッシュトークン。省略可能。
    """
    access_token: str  # JWT アクセストークン
    token_type: str  # トークンのタイプ（例: "bearer"）
    refresh_token: Optional[str] = None  # JWT リフレッシュトークン
