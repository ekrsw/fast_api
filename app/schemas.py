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
    
    name: str # カスタムバリデーションで検証
    @field_validator('name')
    def name_must_not_be_empty(cls, v):
        if not v.strip():
            raise ValueError('Name must not be empty')
        return v

    class Config:
        from_attributes = True
        model_config = ConfigDict()

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
        model_config = ConfigDict()

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
    username: str
    password: str

    @field_validator('username')
    def username_valid(cls, v):
        if not v.strip():
            raise ValueError('Username must not be empty')
        if len(v) < 3 or len(v) > 50:
            raise ValueError('Username must be between 3 and 50 characters')
        return v

    @field_validator('password')
    def password_valid(cls, v):
        if not v.strip():
            raise ValueError('Password must not be empty')
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v

    class Config:
        from_attributes = True
        model_config = ConfigDict()


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
    username: Optional[str] = None
    password: Optional[str] = None
    is_admin: Optional[bool] = None

    @field_validator('username')
    def username_valid(cls, v):
        if v is not None:
            if not v.strip():
                raise ValueError('Username must not be empty')
            if len(v) < 3 or len(v) > 50:
                raise ValueError('Username must be between 3 and 50 characters')
        return v

    @field_validator('password')
    def password_valid(cls, v):
        if v is not None:
            if not v.strip():
                raise ValueError('Password must not be empty')
            if len(v) < 6:
                raise ValueError('Password must be at least 6 characters long')
        return v

    class Config:
        from_attributes = True
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

    class Config:
        from_attributes = True
        model_config = ConfigDict()
