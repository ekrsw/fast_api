import os
from sqlalchemy.orm import Session
from . import models, schemas, crud, auth, database
from dotenv import load_dotenv

# .env ファイルの読み込み
load_dotenv()

# 初期管理者アカウントを作成する関数
def create_initial_admin():
    """
    初期管理者アカウントを作成します。
    環境変数からユーザー名とパスワードを取得し、既存の管理者がいない場合のみ新たに作成します。
    """
    db = database.SessionLocal()
    username = os.getenv("INITIAL_ADMIN_USERNAME")
    password = os.getenv("INITIAL_ADMIN_PASSWORD")

    # ユーザー名やパスワードが設定されていない場合はエラーメッセージを表示し終了
    if not username or not password:
        print("INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD must be set in .env")
        return

    # 既に管理者が存在するか確認
    existing_admin = crud.get_user_by_username(db, username=username)
    if existing_admin:
        print("Admin user already exists.")
        return

    # 管理者ユーザーを作成
    admin_user = crud.create_user(
        db,
        schemas.UserCreate(username=username, password=password),
        is_admin=True
    )
    print(f"Admin user created: {admin_user.username}")

# スクリプトが直接実行された場合、create_initial_admin関数を呼び出して管理者を作成
if __name__ == "__main__":
    create_initial_admin()
