from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator
from fastapi import FastAPI, Response, Depends, HTTPException, Request, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.database import get_async_session
from app import models, schemas, security
from app.models import Category, Product, User
from app.schemas import UserCreate
from app.security import verify_password
import bcrypt
from itsdangerous import URLSafeSerializer
from app.database import async_session
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from redis import asyncio as aioredis
from dotenv import load_dotenv
import os
import html
from pydantic import ValidationError
from app.utils.logging import log_user_action, format_log_details, UserActions

application = FastAPI()

limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"])

# Configure Jinja2 with explicit autoescape
templates = Jinja2Templates(directory="app/templates")
templates.env.autoescape = True

# Add custom filter for extra HTML escaping when needed
templates.env.filters['escape_special'] = lambda value: html.escape(str(value), quote=True)

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

@application.get("/csrf-token")
async def get_csrf_token(response: Response):
    try:
        # Генерируем простой токен без сериализации
        csrf_token = os.urandom(32).hex()
        
        # Устанавливаем токен в куки
        response.set_cookie(
            key="fastapi-csrf-token",
            value=csrf_token,
            httponly=False,
            samesite="strict",
            secure=False,  # В продакшене установить True
            path="/"
        )
        
        print(f"Generated CSRF token: {csrf_token}")  # Отладочная информация
        return {"token": csrf_token}
    except Exception as e:
        print(f"Error generating CSRF token: {e}")  # Отладочная информация
        raise HTTPException(
            status_code=500,
            detail="Ошибка генерации токена безопасности"
        )

@application.middleware("http")
async def csrf_middleware(request: Request, call_next):
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return await call_next(request)

    try:
        csrf_from_header = request.headers.get("X-CSRF-Token")
        csrf_from_cookie = request.cookies.get("fastapi-csrf-token")

        print(f"CSRF from header: {csrf_from_header}")  # Отладочная информация
        print(f"CSRF from cookie: {csrf_from_cookie}")  # Отладочная информация

        if not csrf_from_header or not csrf_from_cookie:
            print("Missing CSRF token")  # Отладочная информация
            return JSONResponse(
                {"detail": "CSRF token missing"}, 
                status_code=403
            )

        # Простое сравнение токенов
        if csrf_from_header != csrf_from_cookie:
            print("CSRF token mismatch")  # Отладочная информация
            return JSONResponse(
                {"detail": "CSRF token mismatch"}, 
                status_code=403
            )

        return await call_next(request)
    except Exception as e:
        print(f"CSRF middleware error: {e}")  # Отладочная информация
        return JSONResponse(
            {"detail": "Security check failed"}, 
            status_code=403
        )

@application.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Add Content Security Policy header
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self'"
    )
    
    # Add other security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    return response

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
    try:
        db_user = await authenticate_user(db, user.email, user.password)
        access_token = security.create_access_token(data={"sub": db_user.email})

        # Логируем успешный вход
        await log_user_action(
            db=db,
            user=db_user,
            action=UserActions.LOGIN,
            details=format_log_details({"email": db_user.email}),
            request=request
        )
        
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            samesite="lax",
            max_age=1800
        )
        
        return {"status": "success", "redirect": "/"}

    except HTTPException as e:
        # Логируем неудачную попытку входа
        if e.status_code == 401:  # Неверный пароль
            result = await db.execute(select(models.User).filter(models.User.email == user.email))
            failed_user = result.scalars().first()
            if failed_user:
                await log_user_action(
                    db=db,
                    user=failed_user,
                    action="login_failed",
                    details="Неверный пароль",
                    request=request
                )
        raise e

# Страница логина
@application.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


# Эндпоинт регистрации
@application.post("/register")
async def register(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    try:
        user_data = await request.json()
        print(f"Received registration data: {user_data}")  # Логируем полученные данные
        
        try:
            # Создаем объект UserCreate
            user = schemas.UserCreate(
                email=security.sanitize_input(user_data.get('email')),
                password=user_data.get('password'),
                first_name=security.sanitize_input(user_data.get('first_name')),
                last_name=security.sanitize_input(user_data.get('last_name')),
                phone=security.sanitize_input(user_data.get('phone')),
                address=security.sanitize_input(user_data.get('address'))
            )
            print("UserCreate object created successfully")  # Логируем успешное создание объекта
        except ValidationError as e:
            print(f"Validation error: {str(e)}")  # Логируем ошибку валидации
            return JSONResponse(
                status_code=422,
                content={"detail": "Ошибка валидации данных", "errors": e.errors()}
            )
        
        # Проверка существующего пользователя
        result = await db.execute(select(models.User).filter(models.User.email == user.email))
        existing_user = result.scalars().first()
        if existing_user:
            print(f"User with email {user.email} already exists")  # Логируем существующего пользователя
            return JSONResponse(
                status_code=400,
                content={"detail": "Пользователь с таким email уже зарегистрирован"}
            )

        try:
            # Хешируем пароль
            hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
            print("Password hashed successfully")  # Логируем успешное хеширование
        except Exception as e:
            print(f"Error hashing password: {str(e)}")  # Логируем ошибку хеширования
            raise

        try:
            # Создаем нового пользователя
            new_user = models.User(
                first_name=user.first_name,
                last_name=user.last_name,
                email=user.email,
                phone=user.phone,
                address=user.address,
                registration_date=datetime.now(timezone.utc).replace(tzinfo=None),
                password=hashed_password.decode('utf-8'),
            )
            print("User object created successfully")  # Логируем создание объекта пользователя

            db.add(new_user)
            await db.commit()
            await db.refresh(new_user)
            print("User saved to database successfully")  # Логируем успешное сохранение

            # Логируем регистрацию
            await log_user_action(
                db=db,
                user=new_user,
                action=UserActions.REGISTER,
                details=format_log_details({
                    "email": new_user.email,
                    "first_name": new_user.first_name,
                    "last_name": new_user.last_name
                }),
                request=request
            )
            print("User action logged successfully")  # Логируем успешное логирование

            # Создаем токен доступа
            access_token = security.create_access_token(data={"sub": new_user.email})
            print("Access token created successfully")  # Логируем создание токена
            
            response.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                samesite="lax",
                max_age=1800
            )
            
            return JSONResponse(
                status_code=200,
                content={"status": "success", "redirect": "/login"}
            )

        except Exception as e:
            print(f"Error creating user: {str(e)}")  # Логируем ошибку создания пользователя
            raise

    except Exception as e:
        print(f"Error during registration: {str(e)}")  # Детальное логирование ошибки
        print(f"Error type: {type(e)}")  # Логируем тип ошибки
        import traceback
        print(f"Traceback: {traceback.format_exc()}")  # Логируем полный стек ошибки
        await db.rollback()  # Откатываем транзакцию в случае ошибки
        return JSONResponse(
            status_code=500,
            content={"detail": f"Ошибка при регистрации пользователя: {str(e)}"}
        )

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
    user_data: dict,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(login_required)
):
    try:
        sanitized_data = {
            key: security.sanitize_input(value)
            for key, value in user_data.items()
            if key not in ['password']
        }
        
        # Сохраняем старые данные для лога
        old_data = {
            "email": current_user.email,
            "phone": current_user.phone,
            "first_name": current_user.first_name,
            "last_name": current_user.last_name,
            "address": current_user.address
        }

        # Обновляем данные пользователя
        if "first_name" in sanitized_data:
            current_user.first_name = sanitized_data["first_name"]
        if "email" in sanitized_data:
            current_user.email = sanitized_data["email"]
        if "phone" in sanitized_data:
            current_user.phone = sanitized_data["phone"]
        if "address" in sanitized_data:
            current_user.address = sanitized_data["address"]
        
        await db.commit()

        # Логируем изменения
        await log_user_action(
            db=db,
            user=current_user,
            action=UserActions.PROFILE_UPDATE,
            details=format_log_details({
                "old_data": old_data,
                "new_data": sanitized_data
            }),
            request=request
        )

        return JSONResponse(
            status_code=200,
            content={"status": "success", "message": "Профиль успешно обновлен"}
        )
        
    except Exception as e:
        await db.rollback()
        print(f"Error updating profile: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Ошибка при обновлении профиля"}
        )

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
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user:
        await log_user_action(
            db=db,
            user=current_user,
            action=UserActions.LOGOUT,
            details=None,
            request=request
        )

    response = RedirectResponse(url="/login")
    response.delete_cookie(
        key="access_token",
        path="/",
        secure=False,
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

@application.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    # Check for potential XSS patterns in the request
    potential_xss = False
    suspicious_patterns = ['<script>', 'javascript:', 'onerror=', 'onload=', 'eval(']
    
    # Check URL parameters
    for param in request.query_params.values():
        if any(pattern.lower() in param.lower() for pattern in suspicious_patterns):
            potential_xss = True
            break
    
    # Check headers
    for header in request.headers.values():
        if any(pattern.lower() in header.lower() for pattern in suspicious_patterns):
            potential_xss = True
            break
    
    if potential_xss:
        # Log the attempt (you should implement proper logging)
        print(f"Potential XSS attempt detected from IP: {request.client.host}")
        return templates.TemplateResponse(
            "error.html",
            {
                "request": request,
                "error": "Обнаружена потенциальная угроза безопасности"
            },
            status_code=400
        )
    
    # Handle other exceptions normally
    return templates.TemplateResponse(
        "error.html",
        {
            "request": request,
            "error": exc.detail
        },
        status_code=exc.status_code
    )
