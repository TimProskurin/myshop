# app/database.py
from sqlalchemy import Engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, Session
from typing import AsyncGenerator
from typing import cast
from contextlib import asynccontextmanager


DATABASE_URL = "postgresql+asyncpg://postgres:Peperonia-2002@localhost:5432/shop2"

# Создаем асинхронный движок
async_engine = create_async_engine(DATABASE_URL, echo=True)

# Создаем базовый класс для всех моделей
Base = declarative_base()

# Создаем фабрику сессий для асинхронного взаимодействия с базой данных
async_session = sessionmaker(
    bind=cast(Engine, async_engine),
    class_=AsyncSession,
    expire_on_commit=False
)

# Функция для получения асинхронной сессии
def get_async_session() -> Session:
    return async_session()