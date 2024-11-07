import asyncio
from . import schemas, crud, database
from .config import settings


async def create_initial_admin() -> None:
    """
    初期管理者ユーザーを作成します。

    この関数は、設定ファイルから初期管理者のユーザー名とパスワードを取得し、
    データベースに管理者ユーザーが存在しない場合に新たに作成します。

    Returns
    -------
    None
        この関数は値を返しません。結果はコンソールに出力されます。
    """
    async with database.AsyncSessionLocal() as db:
        # 設定ファイルから初期管理者のユーザー名とパスワードを取得
        username = settings.initial_admin_username
        password = settings.initial_admin_password

        # ユーザー名またはパスワードが設定されていない場合は終了
        if not username or not password:
            print("INITIAL_ADMIN_USERNAME and INITIAL_ADMIN_PASSWORD must be set in .env")
            return

        # 既に管理者ユーザーが存在するか確認
        existing_admin = await crud.get_user_by_username(db, username=username)
        if existing_admin:
            print("Admin user already exists.")
            return

        # 新しい管理者ユーザーを作成
        admin_user = await crud.create_user(
            db,
            schemas.UserCreate(username=username, password=password),
            is_admin=True
        )
        print(f"Admin user created: {admin_user.username}")


if __name__ == "__main__":
    asyncio.run(create_initial_admin())
