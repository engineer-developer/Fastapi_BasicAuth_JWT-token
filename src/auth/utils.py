from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

import jwt
from fastapi import Cookie, Depends, HTTPException, status
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from passlib.exc import UnknownHashError
from sqlalchemy.ext.asyncio import AsyncSession

from auth.schemas import TokenData, pwd_context
from config.config import settings
from dao.models import Role, User
from database.database import CommonAsyncScopedSession
from dto.users.utils import fetch_user_by_email


async def get_password_hash(password: str) -> str:
    """Make hashed password from given password"""

    hashed_password = pwd_context.hash(password)
    return hashed_password


async def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check equality given password with hashed password"""

    try:
        is_correct = pwd_context.verify(plain_password, hashed_password)
    except UnknownHashError as exc:
        raise HTTPException(
            status_code=400,
            detail=exc.message,
        )
    return is_correct


async def authenticate_user(
    session: AsyncSession,
    email: str,
    password: str,
) -> User | bool:
    """Authenticate user by email and password"""

    user = await fetch_user_by_email(session, email=email)
    if not user:
        return False
    if not await verify_password(password, user.password.hashed_password):
        return False
    return user


async def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None,
) -> str:
    """Create access-token for tracking user registration"""

    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        payload=to_encode,
        key=settings.auth.secret_key,
        algorithm=settings.auth.algorithm,
    )
    return encoded_jwt


async def get_token_from_cookie(
    token: Annotated[str, Cookie(alias=settings.auth.cookie_key)]
) -> str:
    """Get token from COOKIES"""

    return token


async def get_current_user(
    session: CommonAsyncScopedSession,
    token: Annotated[str, Depends(get_token_from_cookie)],
) -> Optional[User]:
    """Get current logging user"""

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Form"},
    )
    try:
        payload = jwt.decode(
            jwt=token,
            key=settings.auth.secret_key,
            algorithms=[settings.auth.algorithm],
        )
        user_email: str = payload.get("sub")
        if user_email is None:
            raise credentials_exception
        token_data = TokenData(user_email=user_email)
    except InvalidTokenError:
        raise credentials_exception

    current_user = await fetch_user_by_email(
        session,
        email=token_data.user_email,
    )
    if current_user is None:
        raise credentials_exception

    return current_user


async def get_current_active_user(
    current_active_user: Annotated[User, Depends(get_current_user)],
) -> Optional[User]:
    """Get current active login user"""

    if not current_active_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_active_user


async def get_current_active_admin(
    current_active_admin: Annotated[User, Depends(get_current_active_user)],
) -> Optional[User]:
    """Get current active login admin or super_admin"""

    is_contains_any_admin = any(
        [
            role in current_active_admin.roles
            for role in (
                Role.admin,
                Role.super_admin,
            )
        ]
    )
    if not is_contains_any_admin:
        raise HTTPException(
            status_code=400,
            detail="User have not admin rights",
        )
    return current_active_admin
