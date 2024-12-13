from datetime import timedelta
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, ORJSONResponse
from fastapi.templating import Jinja2Templates

from auth.schemas import Credentials, Token
from auth.utils import authenticate_user, create_access_token, get_current_user
from config.config import settings
from dao.models import User
from database.database import CommonAsyncScopedSession

router = APIRouter(tags=["Auth"])


@router.get("/login", response_class=HTMLResponse)
async def login(request: Request) -> HTMLResponse:
    """Authentication form providing login"""

    templates_dir = Path(__file__).parent.parent / "templates"
    templates = Jinja2Templates(directory=templates_dir)
    return templates.TemplateResponse(request, "auth.html")


@router.post("/token", response_model=Token)
async def create_token(
    form_data: Annotated[Credentials, Form()],
    session: CommonAsyncScopedSession,
    response: Response,
) -> Token:
    """
    Get credentials from authentication form, create access_token
    and placed it in cookie.
    """
    incorrect_credentials_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Basic_Form"},
    )

    email = form_data.email
    password = form_data.password

    user = await authenticate_user(session, email, password.get_secret_value())
    if not user:
        raise incorrect_credentials_exception

    access_token_expires = timedelta(
        minutes=settings.auth.access_token_expire_minutes,
    )
    access_token = await create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    response.set_cookie(
        key=settings.auth.cookie_key,
        value=access_token,
        httponly=True,
    )
    return Token(access_token=access_token, token_type="JWT")


@router.get("/logout", response_class=ORJSONResponse)
async def logout(
    current_active_user: Annotated[User, Depends(get_current_user)],
    response: Response,
) -> dict[str, bool]:
    """Delete access-token from cookies"""

    response.delete_cookie(settings.auth.cookie_key)
    return {"logout success": True}
