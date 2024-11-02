from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

# .env ファイルの読み込み
load_dotenv()

# データベース接続設定を環境変数から取得し、デフォルト値を指定
DATABASE_HOST = os.getenv("DATABASE_HOST", "db")  # ホスト名
DATABASE_PORT = os.getenv("DATABASE_PORT", "5432")  # ポート番号
DATABASE_USER = os.getenv("DATABASE_USER", "postgres")  # ユーザー名
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "postgres")  # パスワード
DATABASE_NAME = os.getenv("DATABASE_NAME", "postgres")  # データベース名

# データベース接続URLを生成
DATABASE_URL = f"postgresql://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_HOST}:{DATABASE_PORT}/{DATABASE_NAME}"

# SQLAlchemyエンジンを作成して、データベース接続を管理
engine = create_engine(DATABASE_URL)

# セッション作成用のクラスを定義（自動コミットや自動フラッシュは無効）
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 基本のマッピングクラスを作成するためのベースクラスを生成
Base = declarative_base()
