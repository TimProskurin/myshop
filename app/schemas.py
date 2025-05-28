from pydantic import BaseModel, EmailStr
from typing import Optional

class UserBase(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone: str
    address: str

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    status: str
    redirect: str

class UserInDB(UserBase):
    user_id: int
    password: str