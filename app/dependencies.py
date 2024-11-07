from .database import AsyncSessionLocal
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
