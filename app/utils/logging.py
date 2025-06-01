from datetime import datetime
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import UserLog, User
import json

async def log_user_action(
    db: AsyncSession,
    user: User,
    action: str,
    details: dict,
    request: Request
) -> None:
    """
    Логирует действие пользователя в базу данных.
    
    Args:
        db: Сессия базы данных
        user: Объект пользователя
        action: Тип действия
        details: Словарь с деталями действия
        request: Объект запроса FastAPI
    """
    try:
        # Создаем запись лога
        log_entry = UserLog(
            user_id=user.user_id,
            action=action,
            new_data=details,  # Используем details как new_data
            old_data=None,  # Для большинства действий old_data не требуется
            changed_at=datetime.utcnow()
        )
        
        db.add(log_entry)
        await db.commit()
        
    except Exception as e:
        print(f"Ошибка при создании лога: {str(e)}")
        await db.rollback()

def format_log_details(details: dict) -> dict:
    """
    Форматирует детали для логирования.
    
    Args:
        details: Словарь с деталями для логирования
    
    Returns:
        dict: Отформатированный словарь для логирования
    """
    return details  # Возвращаем словарь как есть, так как теперь используем JSON

# Константы для типов действий
class UserActions:
    LOGIN = "login"
    LOGOUT = "logout"
    REGISTER = "register"
    PROFILE_UPDATE = "profile_update"
    PASSWORD_CHANGE = "password_change"
    ORDER_CREATE = "order_create"
    ORDER_STATUS_CHANGE = "order_status_change"
    CART_UPDATE = "cart_update"
    PRODUCT_VIEW = "product_view"
    CATEGORY_VIEW = "category_view" 