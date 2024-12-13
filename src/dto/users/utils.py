from typing import Annotated, Optional, Sequence

from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from dao.models import User
from database.database import CommonAsyncScopedSession


async def fetch_all_users(session: AsyncSession) -> Sequence[User]:
    """Fetch all users from database"""

    stmt = select(User).order_by(User.id)
    result = await session.execute(stmt)
    users = result.scalars().all()
    return users


async def fetch_user_by_id(
    session: AsyncSession,
    id: int,
) -> Optional[User]:
    """Fetch user by id from database"""

    stmt = select(User).where(User.id == id)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    return user


async def fetch_user_by_username(
    session: AsyncSession,
    username: str,
) -> Optional[User]:
    """Fetch user by username from database"""

    stmt = select(User).where(User.username == username)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    return user


async def fetch_user_by_email(
    session: AsyncSession,
    email: str,
) -> Optional[User]:
    """Fetch user by email from database"""

    stmt = select(User).where(User.email == email)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()
    return user
