# FastAPI APIサーバー

## 概要

このプロジェクトは、FastAPIを用いたシンプルなAPIサーバーです。SQLAlchemyでPostgreSQLと連携し、DockerおよびDocker Composeでコンテナ化されています。Nginxをリバースプロキシとして使用しています。

## セットアップ手順

1. **リポジトリのクローン**

   ```bash
   git clone https://github.com/ekrsw/fast_api.git
   cd fast_api
   docker-compose up --build -d
