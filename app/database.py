from sqlalchemy import create_engine, Engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, Session
from typing import AsyncGenerator
from typing import cast
from contextlib import asynccontextmanager

# Асинхронная конфигурация базы данных
DATABASE_URL_ASYNC = "postgresql+asyncpg://postgres:Peperonia-2002@db:5432/shop2"

# Создаем асинхронный движок
async_engine = create_async_engine(
    DATABASE_URL_ASYNC,
    echo=True,
    pool_size=10,         # Размер пула
    max_overflow=20,      # Максимальное превышение пула
    pool_timeout=30,      # Таймаут ожидания соединения
    pool_recycle=3600,    # Время жизни соединения (в секундах)
)

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


# Синхронная конфигурация базы данных для Alembic
DATABASE_URL_SYNC = "postgresql://postgres:Peperonia-2002@db:5432/shop2"

# Создаем синхронный движок для Alembic
sync_engine = create_engine(
    DATABASE_URL_SYNC,
    echo=True,
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=3600,
)

# Функция для получения синхронной сессии
def get_sync_session() -> Session:
    return sessionmaker(bind=sync_engine)()