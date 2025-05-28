from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator
#from fastapi import FastAPI, HTTPException, Depends, status, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
#from fastapi.security import OAuth2PasswordRequestForm
#from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.database import get_async_session
from app import models, schemas, security
from app.models import Category, Product, User
from app.schemas import UserCreate
#from app.security import verify_password
import bcrypt
from fastapi import FastAPI, Response, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from itsdangerous import URLSafeSerializer
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import async_session
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from redis import asyncio as aioredis
from dotenv import load_dotenv
import os
application = FastAPI()

limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"])

templates = Jinja2Templates(directory="app/templates", auto_reload=True)

application.mount("/static", StaticFiles(directory="app/static"), name="static")

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")

# Получение асинхронной сессии
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with get_async_session() as session:
        yield session

async def authenticate_user(db: AsyncSession, email: str, password: str):
    result = await db.execute(select(models.User).where(models.User.email == email))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):  # Сравниваем пароли
        raise HTTPException(status_code=401, detail="Неверный пароль")
    return user

redis_client = aioredis.from_url(
    "redis://redis:6379/0",  # redis — имя сервиса в Docker Compose
    encoding="utf-8",
    decode_responses=True
)

async def get_redis():
    async with redis_client.client() as conn:
        yield conn

@application.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        content={"detail": "Слишком много попыток. Попробуйте позже."},
        status_code=429
    )
@application.on_event("shutdown")
async def shutdown():
    await async_session().close_all()  # Закрываем все соединения
@application.get("/.well-known/appspecific/com.chrome.devtools.json")
async def ignore_chrome_devtools():
    return Response(status_code=200)

@application.middleware("http")
async def csrf_middleware(request: Request, call_next):
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return await call_next(request)

    csrf_from_header = request.headers.get("X-CSRF-Token")
    csrf_from_cookie = request.cookies.get("fastapi-csrf-token")

    if not csrf_from_header or not csrf_from_cookie:
        return JSONResponse({"detail": "CSRF token missing"}, 403)

    serializer = URLSafeSerializer(SECRET_KEY)
    try:
        data_header = serializer.loads(csrf_from_header)
        data_cookie = serializer.loads(csrf_from_cookie)
    except Exception:
        return JSONResponse({"detail": "Invalid CSRF token"}, 403)

    if data_header != data_cookie:
        return JSONResponse({"detail": "CSRF token mismatch"}, 403)

    return await call_next(request)

@application.get("/csrf-token")
async def get_csrf_token(response: Response):
    serializer = URLSafeSerializer(SECRET_KEY)
    csrf_token = serializer.dumps({"csrf": os.urandom(24).hex()})
    print(f"🔑 Генерация CSRF-токена: {csrf_token}")  # Логирование токена
    response.set_cookie(
        key="fastapi-csrf-token",
        value=csrf_token,
        httponly=False,
        samesite="strict",
        secure=False,
        path="/",
    )
    return {"message": "CSRF token generated"}

# Эндпоинт авторизации (логин)
@limiter.limit("5/minute")
@application.post("/login")
async def login(
        user: schemas.UserLogin,
        request: Request,
        response: Response,
        db: AsyncSession = Depends(get_db),
        redis: aioredis.Redis = Depends(get_redis)
):
    # 1. Проверка брутфорса через Redis
    ip = request.client.host
    attempts_key = f"auth_attempts:{ip}"
    block_key = f"auth_block:{ip}"

    # Проверяем блокировку
    if await redis.exists(block_key):
        raise HTTPException(status_code=429, detail="Слишком много попыток. Попробуйте через 1 минуту")

    # Получаем текущее количество попыток
    current_attempts = await redis.get(attempts_key)
    current_attempts = int(current_attempts) if current_attempts else 0

    # Лимит: 5 попыток в минуту
    if current_attempts >= 5:
        await redis.setex(block_key, timedelta(minutes=1).seconds, "1")
        await redis.delete(attempts_key)
        raise HTTPException(status_code=429, detail="Превышено количество попыток")

    try:
        # 2. Ваша существующая логика аутентификации
        db_user = await authenticate_user(db, user.email, user.password)
        access_token = security.create_access_token(data={"sub": db_user.email})

        # Сбрасываем счетчик попыток при успехе
        await redis.delete(attempts_key)
        
        # Устанавливаем токен в куки
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            samesite="lax",
            max_age=1800  # 30 минут
        )
        
        return {"status": "success", "redirect": "/"}

    except HTTPException as e:
        # Увеличиваем счетчик при неудаче
        await redis.incr(attempts_key)
        await redis.expire(attempts_key, timedelta(minutes=1).seconds)
        raise e

# Страница логина
@application.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


# Эндпоинт регистрации
@application.post("/register", response_model=schemas.Token)
async def register(
    user: UserCreate,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    # Проверка существующего пользователя
    result = await db.execute(select(models.User).filter(models.User.email == user.email))
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Пользователь с таким email уже зарегистрирован")

    new_user = models.User(
        first_name=user.first_name,
        last_name=user.last_name,
        email=user.email,
        phone=user.phone,
        address=user.address,
        registration_date=datetime.now(timezone.utc).replace(tzinfo=None),
        password=user.password,
    )

    db.add(new_user)
    try:
        await db.commit()
    except Exception as e:
        await db.rollback()
        print(f"Ошибка при коммите: {e}")
        raise HTTPException(status_code=400, detail=f"Ошибка при регистрации пользователя: {str(e)}")

    await db.refresh(new_user)

    print(f"Создание токена для: {new_user.email}")
    access_token = security.create_access_token(data={"sub": new_user.email})
    print(f"Токен создан: {access_token}")
    
    # Устанавливаем токен в куки
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        max_age=1800  # 30 минут
    )
    
    return {"status": "success", "redirect": "/"}

@application.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

# Получение текущего пользователя
async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    token = request.cookies.get("access_token")
    if not token:
        return None
    
    try:
        payload = security.decode_access_token(token)
        email = payload.get("sub")
        if email is None:
            return None
        
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalars().first()
        if user is None:
            return None
            
        return user
    except:
        return None

# Защита маршрутов для авторизованных пользователей
async def login_required(request: Request, db: AsyncSession = Depends(get_db)):
    user = await get_current_user(request, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    return user

# Эндпоинт личного кабинета
@application.get("/profile")
async def profile(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(login_required)
):
    try:
        # Получаем заказы пользователя
        result = await db.execute(
            select(models.Order)
            .where(models.Order.user_id == current_user.user_id)
            .order_by(models.Order.order_date.desc())
        )
        orders = result.scalars().all()

        orders_data = []
        for order in orders:
            # Получаем все items для текущего заказа
            items_result = await db.execute(
                select(models.OrderItem, models.Product)
                .join(models.Product, models.OrderItem.product_id == models.Product.product_id)
                .where(models.OrderItem.order_id == order.order_id)
            )
            items = items_result.all()
            
            order_dict = {
                "order_id": order.order_id,
                "order_date": order.order_date.strftime("%d.%m.%Y %H:%M"),
                "status": order.status,
                "total_amount": order.total_amount,
                "address": order.address,
                "items": [{
                    "quantity": item[0].quantity,
                    "price": item[0].price,
                    "product_id": item[0].product_id
                } for item in items]
            }
            orders_data.append(order_dict)

        return templates.TemplateResponse("profile.html", {
            "request": request,
            "user": current_user,
            "orders": orders_data
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Обновление данных пользователя
@application.post("/profile/update")
async def update_profile(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(login_required)
):
    try:
        data = await request.json()
        
        # Проверяем, не занят ли email другим пользователем
        if data.get("email") and data["email"] != current_user.email:
            result = await db.execute(
                select(User).where(User.email == data["email"])
            )
            if result.scalars().first():
                raise HTTPException(status_code=400, detail="Email уже используется")
        
        # Проверяем, не занят ли телефон другим пользователем
        if data.get("phone") and data["phone"] != current_user.phone:
            result = await db.execute(
                select(User).where(User.phone == data["phone"])
            )
            if result.scalars().first():
                raise HTTPException(status_code=400, detail="Телефон уже используется")
        
        # Обновляем данные пользователя
        if "first_name" in data:
            current_user.first_name = data["first_name"]
        if "email" in data:
            current_user.email = data["email"]
        if "phone" in data:
            current_user.phone = data["phone"]
        
        await db.commit()
        return {"status": "success"}
        
    except HTTPException as e:
        await db.rollback()
        raise e
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# Обновляем существующие маршруты для поддержки авторизации
@application.get("/")
async def index(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        result = await db.execute(select(models.Category))
        categories = result.scalars().all()
        return templates.TemplateResponse("index.html", {
            "request": request,
            "categories": categories,
            "user": current_user
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {e}")

@application.get("/category/{category_id}")
async def category_detail(
    request: Request,
    category_id: int,
    db: AsyncSession = Depends(get_async_session),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Category).filter(Category.category_id == category_id))
    category = result.scalars().first()

    if category is None:
        return {"message": "Category not found"}

    result = await db.execute(select(Product).filter(Product.category_id == category_id))
    products = result.scalars().all()

    return templates.TemplateResponse("category.html", {
        "request": request,
        "category": category,
        "products": products,
        "user": current_user
    })

# Эндпоинт выхода
@application.get("/logout")
async def logout():
    response = RedirectResponse(url="/login")
    response.delete_cookie(
        key="access_token",
        path="/",  # Важно указать путь, чтобы удалить куки для всего домена
        secure=False,  # В продакшене должно быть True
        httponly=True
    )
    return response

# Тест соединения с базой данных
@application.get("/test-db-connection")
async def test_db_connection(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute("SELECT 1")
        return {"status": "DB Connection Successful"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB Error: {e}")

@application.get("/product/{product_id}")
async def product_detail(
    request: Request,
    product_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        result = await db.execute(
            select(Product).where(Product.product_id == product_id)
        )
        product = result.scalars().first()
        
        if product is None:
            raise HTTPException(status_code=404, detail="Товар не найден")
            
        return templates.TemplateResponse("product_detail.html", {
            "request": request,
            "product": product,
            "user": current_user
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
