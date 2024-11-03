from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from . import models, schemas, database, auth, crud
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Optional
from datetime import timedelta
import os
from dotenv import load_dotenv

# .env ファイルの読み込み
load_dotenv()

# FastAPI アプリケーションのインスタンスを作成
app = FastAPI()

# データベースのテーブルを作成
models.Base.metadata.create_all(bind=database.engine)

# OAuth2 パスワード認証を設定し、トークンの取得エンドポイントを指定
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# データベース接続の取得
def get_db():
    """
    データベースセッションを取得するための依存関係。

    Yields:
        Session: データベースセッションオブジェクト。
    """
    db = database.SessionLocal()  # セッションを作成
    try:
        yield db  # データベースセッションを呼び出し元に提供
    finally:
        db.close()  # 最後にセッションを閉じる

# ユーザー認証の関数
def authenticate_user(db: Session, username: str, password: str):
    """
    ユーザー名とパスワードを使用してユーザーを認証します。

    Args:
        db (Session): データベースセッション。
        username (str): 認証するユーザー名。
        password (str): 認証するパスワード。

    Returns:
        Union[models.User, bool]: 認証に成功した場合はユーザーオブジェクト、失敗した場合はFalse。
    """
    user = crud.get_user_by_username(db, username)  # ユーザー名でユーザーを取得
    if not user:
        return False  # ユーザーが存在しない場合は False を返す
    if not auth.verify_password(password, user.hashed_password):
        return False  # パスワードが一致しない場合も False を返す
    return user  # 認証成功時にユーザー情報を返す

# アクセストークンの作成
def create_access_token_for_user(data: dict, expires_delta: Optional[timedelta] = None):
    """
    ユーザー用のアクセストークンを作成します。

    Args:
        data (dict): トークンに含めるデータ。
        expires_delta (Optional[timedelta], optional): トークンの有効期限。デフォルトはNone。

    Returns:
        str: 作成されたアクセストークン。
    """
    return auth.create_access_token(data, expires_delta)

# ユーザーの登録エンドポイント
@app.post("/register/", response_model=schemas.User)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    """
    新しいユーザーを登録します。

    Args:
        user (schemas.UserCreate): 登録するユーザーの情報。
        db (Session, optional): データベースセッション。デフォルトはDepends(get_db)。

    Raises:
        HTTPException: ユーザー名が既に登録されている場合。

    Returns:
        schemas.User: 登録されたユーザー情報。
    """
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db=db, user=user)

# ユーザーのログインエンドポイント
@app.post("/token", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    ログインしてアクセストークンを取得します。

    Args:
        form_data (OAuth2PasswordRequestForm, optional): フォームデータからユーザー名とパスワードを取得。
        db (Session, optional): データベースセッション。

    Raises:
        HTTPException: 認証に失敗した場合。

    Returns:
        dict: アクセストークンとトークンタイプを含む辞書。
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)))
    access_token = create_access_token_for_user(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# 現在のユーザーの取得
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    現在の認証済みユーザーを取得します。

    Args:
        token (str, optional): 認証トークン。
        db (Session, optional): データベースセッション。

    Raises:
        HTTPException: 認証情報の検証に失敗した場合。

    Returns:
        models.User: 現在のユーザーオブジェクト。
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception
    return user

# アイテムの作成エンドポイント
@app.post("/items/", response_model=schemas.Item)
def create_item(
    item: schemas.ItemCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """
    新しいアイテムを作成します。

    Args:
        item (schemas.ItemCreate): 作成するアイテムの情報。
        db (Session, optional): データベースセッション。
        current_user (schemas.User, optional): 現在のユーザー。

    Returns:
        schemas.Item: 作成されたアイテム。
    """
    db_item = models.Item(name=item.name)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item

# アイテムの取得エンドポイント
@app.get("/items/", response_model=List[schemas.Item])
def read_items(
    skip: int = 0,
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """
    アイテムのリストを取得します。

    Args:
        skip (int, optional): スキップする件数。デフォルトは0。
        limit (int, optional): 取得する最大件数。デフォルトは10。
        db (Session, optional): データベースセッション。
        current_user (schemas.User, optional): 現在のユーザー。

    Returns:
        List[schemas.Item]: アイテムのリスト。
    """
    items = db.query(models.Item).offset(skip).limit(limit).all()
    return items

# 特定のアイテムを取得
@app.get("/items/{item_id}", response_model=schemas.Item)
def read_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """
    指定されたIDのアイテムを取得します。

    Args:
        item_id (int): アイテムのID。
        db (Session, optional): データベースセッション。
        current_user (schemas.User, optional): 現在のユーザー。

    Raises:
        HTTPException: アイテムが見つからない場合。

    Returns:
        schemas.Item: 取得したアイテム。
    """
    item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

# アイテムの更新エンドポイント
@app.put("/items/{item_id}", response_model=schemas.Item)
def update_item(
    item_id: int,
    item: schemas.ItemCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """
    指定されたIDのアイテムを更新します。

    Args:
        item_id (int): アイテムのID。
        item (schemas.ItemCreate): 更新するアイテムの情報。
        db (Session, optional): データベースセッション。
        current_user (schemas.User, optional): 現在のユーザー。

    Raises:
        HTTPException: アイテムが見つからない場合。

    Returns:
        schemas.Item: 更新されたアイテム。
    """
    db_item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if db_item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    db_item.name = item.name
    db.commit()
    db.refresh(db_item)
    return db_item

# アイテムの削除エンドポイント
@app.delete("/items/{item_id}", response_model=dict)
def delete_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """
    指定されたIDのアイテムを削除します。

    Args:
        item_id (int): 削除するアイテムのID。
        db (Session, optional): データベースセッション。
        current_user (schemas.User, optional): 現在のユーザー。

    Raises:
        HTTPException: アイテムが見つからない場合。

    Returns:
        dict: 削除の結果を示すメッセージ。
    """
    db_item = db.query(models.Item).filter(models.Item.id == item_id).first()
    if db_item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    db.delete(db_item)
    db.commit()
    return {"detail": "Item deleted"}
