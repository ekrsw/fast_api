from pydantic import BaseModel
from datetime import datetime

class ItemBase(BaseModel):
    name: str

class ItemCreate(ItemBase):
    pass

class Item(ItemBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    username: str
    password: str

class User(BaseModel):
    id: int
    username: str
    is_admin: bool  # 管理者フラグを含める

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str