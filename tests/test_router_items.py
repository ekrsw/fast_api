# tests/test_router_items.py

import pytest
import uuid
from httpx import AsyncClient

from sqlalchemy.ext.asyncio import AsyncSession

from app import schemas, crud
from app.auth import create_access_token
from app.config import settings
from datetime import timedelta


@pytest.fixture
def unique_item_name():
    """Generate a unique item name for testing."""
    return f"item_{uuid.uuid4()}"


@pytest.fixture
def unique_username():
    """Generate a unique username for testing."""
    return f"user_{uuid.uuid4()}"


@pytest.mark.asyncio
async def test_create_item(client: AsyncClient, db_session: AsyncSession, unique_item_name: str, unique_username: str):
    """
    Test creating a new item.

    This test ensures that a new item can be created when a valid access token is provided.
    """
    # Create a test user
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # Generate access token
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # Prepare headers with authorization
    headers = {"Authorization": f"Bearer {access_token}"}

    # Item data
    item_data = {"name": unique_item_name}

    # Make request to create item
    response = await client.post("/items/", json=item_data, headers=headers)

    assert response.status_code == 200, f"Failed to create item: {response.text}"
    item = response.json()
    assert item["name"] == unique_item_name, "Item name does not match"
    assert "id" in item, "Item ID not returned"
    assert "created_at" in item, "Item creation timestamp not returned"
    assert "updated_at" in item, "Item update timestamp not returned"


@pytest.mark.asyncio
async def test_read_items(client: AsyncClient, db_session: AsyncSession, unique_item_name: str, unique_username: str):
    """
    Test reading multiple items.

    This test ensures that multiple items can be retrieved when a valid access token is provided.
    """
    # Create a test user
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # Generate access token
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # Prepare headers with authorization
    headers = {"Authorization": f"Bearer {access_token}"}

    # Create multiple items
    item_names = [f"item_{uuid.uuid4()}" for _ in range(5)]
    for name in item_names:
        item_data = {"name": name}
        await client.post("/items/", json=item_data, headers=headers)

    # Make request to read items
    response = await client.get("/items/", headers=headers)

    assert response.status_code == 200, f"Failed to read items: {response.text}"
    items = response.json()
    retrieved_names = [item["name"] for item in items]
    for name in item_names:
        assert name in retrieved_names, f"Item {name} not found in retrieved items"


@pytest.mark.asyncio
async def test_read_item(client: AsyncClient, db_session: AsyncSession, unique_item_name: str, unique_username: str):
    """
    Test reading a specific item.

    This test ensures that a specific item can be retrieved by ID when a valid access token is provided.
    """
    # Create a test user
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # Generate access token
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # Prepare headers with authorization
    headers = {"Authorization": f"Bearer {access_token}"}

    # Create an item
    item_data = {"name": unique_item_name}
    create_response = await client.post("/items/", json=item_data, headers=headers)
    item = create_response.json()
    item_id = item["id"]

    # Make request to read the item
    response = await client.get(f"/items/{item_id}", headers=headers)

    assert response.status_code == 200, f"Failed to read item: {response.text}"
    retrieved_item = response.json()
    assert retrieved_item["id"] == item_id, "Item ID does not match"
    assert retrieved_item["name"] == unique_item_name, "Item name does not match"


@pytest.mark.asyncio
async def test_update_item(client: AsyncClient, db_session: AsyncSession, unique_item_name: str, unique_username: str):
    """
    Test updating an item.

    This test ensures that an item can be updated when a valid access token is provided.
    """
    # Create a test user
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # Generate access token
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # Prepare headers with authorization
    headers = {"Authorization": f"Bearer {access_token}"}

    # Create an item
    item_data = {"name": unique_item_name}
    create_response = await client.post("/items/", json=item_data, headers=headers)
    item = create_response.json()
    item_id = item["id"]

    # Update data
    updated_name = "Updated Item Name"
    update_data = {"name": updated_name}

    # Make request to update the item
    response = await client.put(f"/items/{item_id}", json=update_data, headers=headers)

    assert response.status_code == 200, f"Failed to update item: {response.text}"
    updated_item = response.json()
    assert updated_item["id"] == item_id, "Item ID does not match"
    assert updated_item["name"] == updated_name, "Item name was not updated"


@pytest.mark.asyncio
async def test_delete_item(client: AsyncClient, db_session: AsyncSession, unique_item_name: str, unique_username: str):
    """
    Test deleting an item.

    This test ensures that an item can be deleted when a valid access token is provided.
    """
    # Create a test user
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # Generate access token
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # Prepare headers with authorization
    headers = {"Authorization": f"Bearer {access_token}"}

    # Create an item
    item_data = {"name": unique_item_name}
    create_response = await client.post("/items/", json=item_data, headers=headers)
    item = create_response.json()
    item_id = item["id"]

    # Make request to delete the item
    response = await client.delete(f"/items/{item_id}", headers=headers)

    assert response.status_code == 200, f"Failed to delete item: {response.text}"
    detail = response.json()
    assert detail["detail"] == "Item deleted", "Unexpected deletion detail message"

    # Verify that the item no longer exists
    get_response = await client.get(f"/items/{item_id}", headers=headers)
    assert get_response.status_code == 404, "Deleted item should not be retrievable"


@pytest.mark.asyncio
async def test_unauthorized_access(client: AsyncClient):
    """
    Test unauthorized access to item endpoints.

    This test ensures that accessing item endpoints without a valid token results in a 401 error.
    """
    # Attempt to access items endpoint without token
    response = await client.get("/items/")
    assert response.status_code == 401, "Unauthorized access should return 401"
    assert response.json()["detail"] == "Not authenticated", "Unexpected error message"


@pytest.mark.asyncio
async def test_update_nonexistent_item(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    Test updating a non-existent item.

    This test ensures that updating a non-existent item returns a 404 error.
    """
    # Create a test user
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # Generate access token
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # Prepare headers with authorization
    headers = {"Authorization": f"Bearer {access_token}"}

    # Update data
    updated_name = "Updated Item Name"
    update_data = {"name": updated_name}

    # Use a non-existent item ID
    non_existent_item_id = 9999

    # Make request to update the non-existent item
    response = await client.put(f"/items/{non_existent_item_id}", json=update_data, headers=headers)

    assert response.status_code == 404, "Updating non-existent item should return 404"
    assert response.json()["detail"] == "Item not found", "Unexpected error message"


@pytest.mark.asyncio
async def test_delete_nonexistent_item(client: AsyncClient, db_session: AsyncSession, unique_username: str):
    """
    Test deleting a non-existent item.

    This test ensures that deleting a non-existent item returns a 404 error.
    """
    # Create a test user
    password = "testpassword"
    user_create = schemas.UserCreate(username=unique_username, password=password)
    user = await crud.create_user(db_session, user_create)

    # Generate access token
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # Prepare headers with authorization
    headers = {"Authorization": f"Bearer {access_token}"}

    # Use a non-existent item ID
    non_existent_item_id = 9999

    # Make request to delete the non-existent item
    response = await client.delete(f"/items/{non_existent_item_id}", headers=headers)

    assert response.status_code == 404, "Deleting non-existent item should return 404"
    assert response.json()["detail"] == "Item not found", "Unexpected error message"

