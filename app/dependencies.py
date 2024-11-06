from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from .database import SessionLocal

def get_db() -> Session:
    """
    データベースセッションを取得するための依存関係。

    Yields:
        Session: データベースセッションオブジェクト。
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
