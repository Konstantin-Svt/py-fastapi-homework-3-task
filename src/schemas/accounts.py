from pydantic import BaseModel, EmailStr, field_validator, Field, ConfigDict

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    raw_password: str = Field(..., alias="password")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        return accounts_validators.validate_email(v)

    @field_validator("raw_password")
    @classmethod
    def validate_password(cls, v):
        return accounts_validators.validate_password_strength(v)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class MessageResponseSchema(BaseModel):
    message: str


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        return accounts_validators.validate_email(v)


class PasswordResetCompleteRequestSchema(UserActivationRequestSchema):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        return accounts_validators.validate_password_strength(v)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
