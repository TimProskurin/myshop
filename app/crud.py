from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models import Category, Product, User


async def get_categories(session: AsyncSession):
    result = await session.execute(select(Category))
    return result.scalars().all()

async def get_products_by_category(session: AsyncSession, category_id: int):
    result = await session.execute(select(Product).filter(Product.category_id == category_id))
    return result.scalars().all()

async def get_users(session: AsyncSession):
    result = await session.execute(select(User))
    return result.scalars().all()
