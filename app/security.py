from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from dotenv import load_dotenv
import os
from fastapi import HTTPException, status
import html
import re


load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY") # Ваш секретный ключ
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Инициализируем контекст для хеширования
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Функция для хеширования пароля
async def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# Функция для проверки пароля
async def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def sanitize_input(value: str) -> str:
    """
    Sanitize user input to prevent XSS attacks.
    """
    if not isinstance(value, str):
        return str(value)
    
    # HTML escape
    value = html.escape(value, quote=True)
    
    # Remove potentially dangerous patterns
    value = re.sub(r'javascript:', '', value, flags=re.IGNORECASE)
    value = re.sub(r'data:', '', value, flags=re.IGNORECASE)
    value = re.sub(r'vbscript:', '', value, flags=re.IGNORECASE)
    
    return value


