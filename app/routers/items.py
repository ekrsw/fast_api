from fastapi import APIRouter, Depends, HTTPException
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from .. import schemas, crud
from ..dependencies import get_db
from ..auth import get_current_user

router = APIRouter(
    prefix="/items",
    tags=["items"],
)

@router.post("/", response_model=schemas.Item)
async def create_item(
    item: schemas.ItemCreate,
    db: AsyncSession = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
) -> schemas.Item:
    return await crud.create_item(db=db, item=item)

@router.get("/", response_model=List[schemas.Item])
async def read_items(
    skip: int = 0,
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
) -> List[schemas.Item]:
    return await crud.get_items(db, skip=skip, limit=limit)

@router.get("/{item_id}", response_model=schemas.Item)
async def read_item(
    item_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
) -> schemas.Item:
    db_item = await crud.get_item(db, item_id=item_id)
    if db_item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return db_item

@router.put("/{item_id}", response_model=schemas.Item)
async def update_item(
    item_id: int,
    item: schemas.ItemCreate,
    db: AsyncSession = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
) -> schemas.Item:
    updated_item = await crud.update_item(db=db, item_id=item_id, item=item)
    if updated_item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return updated_item

@router.delete("/{item_id}", response_model=dict)
async def delete_item(
    item_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
) -> dict:
    deleted_item = await crud.delete_item(db=db, item_id=item_id)
    if deleted_item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"detail": "Item deleted"}
