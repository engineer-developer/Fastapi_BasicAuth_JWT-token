import re
from typing import Annotated

from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field, Secret


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# regex_pattern = re.compile(r"^((?=\S*?[A-Z])(?=\S*?[a-z])(?=\S*?[0-9]).{6,})\S$")
regex_pattern = re.compile(r"^\w{6,10}$")
SecretPassword = Secret[Annotated[str, Field(pattern=regex_pattern)]]


class Credentials(BaseModel):
    email: EmailStr
    password: SecretPassword


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    user_email: EmailStr
