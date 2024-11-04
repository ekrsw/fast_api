# FastAPI APIサーバー

## 概要

このプロジェクトは、FastAPIを用いたシンプルなAPIサーバーです。SQLAlchemyでPostgreSQLと連携し、DockerおよびDocker Composeでコンテナ化されています。Nginxをリバースプロキシとして使用しています。

## セットアップ手順

1. **リポジトリのクローン**
   ```bash
   git clone https://github.com/ekrsw/fast_api.git
2. **コンテナを起動**
   ```bash
   cd fast_api
   docker-compose up -build -d
3. **管理者ユーザーを作成**
   ```bash
   docker-compose exec api python -m app.create_admin
4. **アクセストークンの取得**
   ```bash
   curl -X POST "http://localhost:8080/token" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=admin&password=my_admin_password"
   ```
   以下のようにレスポンスが返ってきます。
   ```bash
   {
   "access_token": "取得したアクセストークンがここに入ります",
   "token_type": "bearer",
   "refresh_token": "取得したリフレッシュトークンがここに入ります"
   }
   ```
5. **リフレッシュトークンを使用して新しいアクセストークンを取得**
   ```bash
   curl -X POST "http://localhost:8080/refresh" \
     -H "refresh-token: 取得したリフレッシュトークンをここに入れます"
   ```
6. **APIのテスト**
   ```bash
   curl -X POST "http://localhost:8080/items/" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer 取得したアクセストークンをここに入れます" \
     -d '{
           "name": "新しいアイテム名"
         }'
## PostgreSQLへ接続
   ```bash
   docker exec -it fast_api-db-1 psql -U [DATABASE_USER] [DATABASE_NAME]
   ```