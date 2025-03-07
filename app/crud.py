from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models import Category, Product, User
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt

SECRET_KEY = "secret_key"  # Ваш секретный ключ
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

async def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_categories(session: AsyncSession):
    result = await session.execute(select(Category))
    return result.scalars().all()

async def get_products_by_category(session: AsyncSession, category_id: int):
    result = await session.execute(select(Product).filter(Product.category_id == category_id))
    return result.scalars().all()

async def get_users(session: AsyncSession):
    result = await session.execute(select(User))
    return result.scalars().all()
