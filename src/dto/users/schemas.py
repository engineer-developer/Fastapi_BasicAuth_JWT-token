import enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class RoleSchema(str, enum.Enum):
    user = "user"
    super_user = "super_user"
    teacher = "teacher"
    moderator = "moderator"
    admin = "admin"
    super_admin = "super_admin"


class UserBaseSchema(BaseModel):
    username: Optional[str]
    email: EmailStr
    roles: list[RoleSchema]


class UserCreateSchema(UserBaseSchema):
    password: str = Field(min_length=10)

    @field_validator("roles")
    @classmethod
    def check_field(cls, v: list):
        if RoleSchema.super_admin in v:
            v.remove(RoleSchema.super_admin)
            v.append(RoleSchema.admin)
        return v


class UserUpdateSchema(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    roles: Optional[list[RoleSchema]] = None
    is_active: Optional[bool] = None


class UserOutSchema(UserBaseSchema):
    model_config = ConfigDict(from_attributes=True)

    id: int
    is_active: bool


class DeleteConfirmSchema(BaseModel):
    deleted: bool


class ErrorDetailSchema(BaseModel):
    detail: str
