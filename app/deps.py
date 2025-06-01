from typing import AsyncGenerator, Annotated, Optional
from fastapi import Depends, Request, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from sqlalchemy.future import select
from app.database import get_async_session
from app.models import User
from app.auth import get_current_user

# Базовая зависимость для сессии БД
DBSession = Annotated[AsyncSession, Depends(get_async_session)]

# Зависимость для получения текущего пользователя (может быть None для публичных маршрутов)
async def get_optional_user(
    request: Request,
    db: DBSession
) -> Optional[User]:
    return await get_current_user(request, db)

# Зависимость для получения авторизованного пользователя (обязательно)
async def get_auth_user(
    request: Request,
    db: DBSession
) -> User:
    user = await get_current_user(request, db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    return user

# Аннотированные зависимости для использования в эндпоинтах
OptionalUser = Annotated[Optional[User], Depends(get_optional_user)]
AuthUser = Annotated[User, Depends(get_auth_user)] 