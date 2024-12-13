from asyncio import current_task
from typing import AsyncGenerator, AsyncIterator

import pytest
from pytest_asyncio.plugin import is_async_test
from fastapi import FastAPI
from sqlalchemy import NullPool
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
    async_scoped_session,
)
from httpx import AsyncClient, ASGITransport

from src.database.database import get_session, get_scoped_session
from src.dao.base_model import metadata
from src.dao.models import Password, User  # noqa
from src.config.config import settings
from src.core.fastapi_factory import create_app


db_url = settings.db.url
print(f"\n{'*' * 70}\n{db_url=}\n{'*' * 70}\n")

engine_test = create_async_engine(
    url=db_url,
    poolclass=NullPool,
    echo=True,
)
async_session = async_sessionmaker(
    engine_test,
    class_=AsyncSession,
    expire_on_commit=False,
)

scoped_session = async_scoped_session(
    session_factory=async_session,
    scopefunc=current_task,
)

metadata.bind = engine_test


async def override_get_async_session() -> AsyncIterator[AsyncSession]:
    async with async_session() as session:
        yield session


async def override_get_scoped_session() -> AsyncIterator[AsyncSession]:
    async with scoped_session() as session:
        yield session


def pytest_collection_modifyitems(items):
    """Function implements to run all tests in the session in the same event loop"""

    pytest_asyncio_tests = (item for item in items if is_async_test(item))
    session_scope_marker = pytest.mark.asyncio(loop_scope="session")
    for async_test in pytest_asyncio_tests:
        async_test.add_marker(session_scope_marker, append=False)


password = Password(
    hashed_password="$2b$12$aToTBlTJQXc4np906GD9KO2ckSvVO5dj3x9ZxAi58MxVFa7wOaBmO",
)
user = User(
    username="some_user",
    email="user@example.com",
    roles=["admin"],
    is_active=True,
    password_id=1,
)


@pytest.fixture(autouse=True, scope="session")
async def prepare_database():
    """
    Create tables in database on startup tests.
    Fill tables with admin user and password.
    At final - delete all tables.
    """

    async with engine_test.begin() as conn:
        await conn.run_sync(metadata.drop_all)
        await conn.run_sync(metadata.create_all)

    async with async_session() as session:
        session.add(password)
        await session.flush()
        session.add(user)
        await session.commit()

    yield
    async with engine_test.begin() as conn:
        await conn.run_sync(metadata.drop_all)


@pytest.fixture(scope="session")
def app():
    """Create app with overrides sessions"""

    _app: FastAPI = create_app()
    _app.dependency_overrides[get_session] = override_get_async_session
    _app.dependency_overrides[get_scoped_session] = override_get_scoped_session
    yield _app


@pytest.fixture(scope="session")
async def async_client(app) -> AsyncGenerator[AsyncClient, None]:
    """Create async client"""

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as async_client:
        yield async_client
