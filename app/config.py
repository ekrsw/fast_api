# app/config.py
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Any

class Settings(BaseSettings):
    # Database Configuration
    database_host: str = Field("db", env="DATABASE_HOST")
    database_port: int = Field(5432, env="DATABASE_PORT")
    database_user: str = Field("admin", env="DATABASE_USER")
    database_password: str = Field("my_database_password", env="DATABASE_PASSWORD")
    database_name: str = Field("my_database", env="DATABASE_NAME")
    
    # API Configuration
    api_host: str = Field("0.0.0.0", env="API_HOST")
    api_port: int = Field(8000, env="API_PORT")
    
    # Nginx Configuration
    nginx_port: int = Field(8080, env="NGINX_PORT")
    
    # JWT Configuration
    secret_key: str = Field(..., env="SECRET_KEY")
    algorithm: str = Field("HS256", env="ALGORITHM")
    access_token_expire_minutes: int = Field(30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_algorithm: str = Field("HS256", env="REFRESH_ALGORITHM")
    refresh_secret_key: str = Field(..., env="REFRESH_SECRET_KEY")
    refresh_token_expire_minutes: int = Field(1440, env="REFRESH_TOKEN_EXPIRE_MINUTES")
    
    # Initial Admin User
    initial_admin_username: str = Field(..., env="INITIAL_ADMIN_USERNAME")
    initial_admin_password: str = Field(..., env="INITIAL_ADMIN_PASSWORD")
    
    class Config:
        env_file = ".env"

settings = Settings()
