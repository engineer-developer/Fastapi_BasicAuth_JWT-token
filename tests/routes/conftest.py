from typing import Optional

import pytest
from httpx import AsyncClient


@pytest.fixture(scope="class")
async def auth_data():
    return {
        "email": "user@example.com",
        "password": "1234567890",
    }


@pytest.fixture(scope="class")
async def login(async_client: AsyncClient, auth_data: dict[str, str]) -> Optional[str]:
    auth_url = "/token"
    auth_headers = {"Content-type": "application/x-www-form-urlencoded"}
    auth_response = await async_client.post(
        auth_url, data=auth_data, headers=auth_headers
    )
    return auth_response.json().get("access_token")


@pytest.fixture
async def new_user():
    return {
        "username": "Bob",
        "email": "bob@example.com",
        "roles": ["user"],
        "password": "0987654321",
    }
