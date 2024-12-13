from typing import Optional

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from src.dao.models import User
from tests.conftest import (
    async_client,
    async_session,
)


async def test_can_get_api_version(async_client: AsyncClient):
    """Test - client can get api version"""

    url = "/api"
    response = await async_client.get(url)
    assert response.status_code == 200, f"Url {url} not reachable"


@pytest.mark.usefixtures("login")
class TestUsers:
    """Tests for all users endpoints"""

    @classmethod
    async def fetch_users_count(cls, session):
        stmt = select(User)
        result = await session.execute(stmt)
        users: list = result.scalars().all()
        return len(users)

    @classmethod
    async def fetch_user_by_id(cls, session, user_id):
        stmt = select(User).where(User.id == user_id)
        result = await session.execute(stmt)
        user: Optional[User] = result.scalar_one_or_none()
        return user

    @classmethod
    async def test_can_get_all_users(
        cls,
        async_client: AsyncClient,
    ):
        """Test - client can get all users"""

        url = "/api/users"
        response = await async_client.get(url)
        assert response.status_code == 200

    @classmethod
    async def test_can_add_new_user_to_db(
        cls,
        async_client: AsyncClient,
        new_user,
    ):
        """Test client can add new user to database"""

        async with async_session() as session:
            user_count_before = await cls.fetch_users_count(session)
            url = "/api/users"
            response = await async_client.post(
                url,
                json=new_user,
            )
            assert response.status_code == 201
            assert response.json()["id"] == 2
            user_count_after = await cls.fetch_users_count(session)
            assert user_count_after - user_count_before == 1

    @classmethod
    async def test_can_get_user_by_id(
        cls,
        async_client: AsyncClient,
    ):
        """Test - client can get user by id"""
        user_id = 2
        url = f"/api/users/{user_id}"
        response = await async_client.get(url)
        assert response.status_code == 200

    @classmethod
    async def test_can_delete_user_from_db(
        cls,
        async_client: AsyncClient,
    ):
        """Test client can delete user from database"""

        async with async_session() as session:
            user_count_before = await cls.fetch_users_count(session)
            user_id = 2
            url = f"/api/users/{user_id}"
            response = await async_client.delete(url)
            assert response.status_code == 200
            assert response.json().get("deleted") is True
            user_count_after = await cls.fetch_users_count(session)
            assert user_count_before - user_count_after == 1
