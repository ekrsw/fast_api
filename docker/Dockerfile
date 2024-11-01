FROM python:3.11-slim

# 作業ディレクトリの設定
WORKDIR /app

# 必要な環境変数を設定
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 依存関係のインストール
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# アプリケーションコードのコピー
COPY ./app /app/app

# Uvicornでアプリケーションを起動
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
