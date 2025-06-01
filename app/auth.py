from fastapi import Request, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import joinedload
from app.models import User
from app import security
from functools import wraps

async def get_current_user(request: Request, db: AsyncSession) -> User:
    token = request.cookies.get("access_token")
    if not token:
        return None
    
    try:
        payload = security.decode_access_token(token)
        email = payload.get("sub")
        if email is None:
            return None
        
        result = await db.execute(
            select(User)
            .options(joinedload(User.roles))
            .where(User.email == email)
        )
        user = result.unique().scalar_one_or_none()
        if user is None:
            return None
            
        return user
    except:
        return None

def admin_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = kwargs.get('request')
        db = kwargs.get('db')
        
        if not request or not db:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Server configuration error"
            )
        
        user = await get_current_user(request, db)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated"
            )
        
        is_admin = any(role.name == 'admin' for role in user.roles)
        if not is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin access required"
            )
        
        return await func(*args, **kwargs)
    return wrapper

async def login_required(request: Request, db: AsyncSession):
    user = await get_current_user(request, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    return user 