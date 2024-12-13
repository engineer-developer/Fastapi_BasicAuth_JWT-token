from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict

env_file = Path(__file__).parent.parent / ".env"


class DatabaseConfig(BaseModel):
    user: str
    password: str
    host: str
    port: str
    name: str

    @property
    def url(self) -> str:
        return "postgresql+asyncpg://{}:{}@{}:{}/{}".format(
            self.user,
            self.password,
            self.host,
            self.port,
            self.name,
        )


class AuthData(BaseModel):
    secret_key: str
    algorithm: str
    access_token_expire_minutes: int = 30
    cookie_key: str = "x-auth-token"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=env_file,
        case_sensitive=False,
        env_nested_delimiter="__",
    )
    db: DatabaseConfig
    auth: AuthData


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
