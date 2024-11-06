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
   
   #### Mac, Linuxの場合
   ```bash
   curl -X POST "http://localhost:8080/auth/token" \
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
   #### Windows Power Shellの場合
   ```Power Shell
   $headers = @{
    "Content-Type" = "application/x-www-form-urlencoded"
   }

   $body = @{
      "username" = "admin"
      "password" = "my_admin_password"
   }

   $response = Invoke-WebRequest -Uri "http://localhost:8080/auth/token" -Method Post -Headers $headers -Body $body
   $json = $response.Content | ConvertFrom-Json

   # トークンを表示
   $accessToken = $json.access_token
   $refreshToken = $json.refresh_token

   Write-Output "Access Token: $accessToken"
   Write-Output "Refresh Token: $refreshToken"
   ```
   以下の様にトークンが表示されます。
   ```
   Access Token: "取得したアクセストークンがここに入ります"
   Refresh Token: "取得したリフレッシュトークンがここに入ります"
   ```

5. **リフレッシュトークンを使用して新しいアクセストークンを取得**

   #### Mac, Linuxの場合
   ```bash
   curl -X POST "http://localhost:8080/auth/refresh" \
     -H "refresh-token: 取得したリフレッシュトークンをここに入れます"
   ```
   #### Windows Power Shellの場合
   ```Power Shell
   $headers = @{
    "refresh-token" = "取得したリフレッシュトークンをここに入れます"
   }

   Invoke-RestMethod -Uri "http://localhost:8080/auth/refresh" -Method Post -Headers $headers
   ```
6. **APIのテスト**
   
   #### Mac, Linuxの場合
   ```bash
   curl -X POST "http://localhost:8080/items/" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer 取得したアクセストークンをここに入れます" \
     -d '{
           "name": "新しいアイテム名"
         }'
   ```
   #### Windows Power Shellの場合
   ```Power Shell
   $headers = @{
    "Content-Type" = "application/json"
    "Authorization" = "Bearer 取得したアクセストークンをここに入れます"
   }

   $body = @{
      "name" = "新しいアイテム名"
   } | ConvertTo-Json

   Invoke-RestMethod -Uri "http://localhost:8080/items/" -Method Post -Headers $headers -Body $body
   ```
## PostgreSQLへ接続
   ```bash
   docker exec -it fast_api-db-1 psql -U [DATABASE_USER] [DATABASE_NAME]
   ```