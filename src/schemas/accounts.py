from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database.validators.accounts import validate_password_strength, validate_email


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return validate_password_strength(v)

    @field_validator("email")
    @classmethod
    def validate_email(cls, e: str) -> str:
        return validate_email(e)

class UserResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

class PasswordResetConfirmSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        return validate_password_strength(v)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenPairResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str
