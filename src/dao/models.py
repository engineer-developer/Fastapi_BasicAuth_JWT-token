import enum
from typing import Optional

from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base_model import DatabaseModel


class Password(DatabaseModel):
    """Passwords table"""

    __tablename__ = "passwords"

    id: Mapped[int] = mapped_column(primary_key=True)
    hashed_password: Mapped[str]

    user: Mapped["User"] = relationship(
        back_populates="password",
        uselist=False,
    )


class Role(enum.Enum):
    user = "user"
    super_user = "super_user"
    teacher = "teacher"
    moderator = "moderator"
    admin = "admin"
    super_admin = "super_admin"


class User(DatabaseModel):
    """Users table"""

    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("password_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[Optional[str]]
    email: Mapped[str] = mapped_column(unique=True)
    roles: Mapped[list[Role]] = mapped_column(ARRAY(PgEnum(Role)))

    is_active: Mapped[bool] = mapped_column(default=True)
    password_id: Mapped[int] = mapped_column(
        ForeignKey(
            "passwords.id",
            ondelete="CASCADE",
        )
    )

    password: Mapped["Password"] = relationship(
        back_populates="user",
        single_parent=True,
        cascade="all, delete-orphan",
        uselist=False,
        lazy="selectin",
    )

    def __repr__(self):
        return f"User <{self.username}>"
