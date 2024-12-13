from pydantic import BaseModel, ConfigDict


class PasswordBaseSchema(BaseModel):
    hashed_password: str


class PasswordCreateSchema(PasswordBaseSchema):
    pass


class PasswordOutSchema(PasswordBaseSchema):
    model_config = ConfigDict(from_attributes=True)

    id: int
