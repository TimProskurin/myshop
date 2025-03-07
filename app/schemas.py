from pydantic import BaseModel, EmailStr, field_validator
from fastapi import Form

class UserCreate(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone: str
    address: str
    password: str
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str | None = None

class UserLogin(BaseModel):
    email: str
    password: str