from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
import re

class UserBase(BaseModel):
    first_name: str = Field(..., min_length=2, max_length=50)
    last_name: str = Field(..., min_length=2, max_length=50)
    email: EmailStr
    phone: str = Field(..., min_length=10, max_length=15)
    address: str = Field(..., min_length=5, max_length=200)

    @validator('first_name', 'last_name')
    def validate_name(cls, v):
        if not re.match(r'^[A-Za-zА-Яа-яЁё\s]{2,50}$', v):
            raise ValueError('Имя и фамилия должны содержать только буквы и пробелы')
        return v

    @validator('phone')
    def validate_phone(cls, v):
        if not re.match(r'^[0-9+]{10,15}$', v):
            raise ValueError('Неверный формат номера телефона')
        return v

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

    @validator('password')
    def validate_password(cls, v):
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', v):
            raise ValueError('Пароль должен содержать минимум 8 символов, включая буквы и цифры')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    status: str
    redirect: str

class UserInDB(UserBase):
    user_id: int
    password: str