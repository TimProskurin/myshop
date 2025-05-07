from datetime import datetime, timezone
from typing import AsyncGenerator
from fastapi import FastAPI, HTTPException, Depends, status, Request, Form
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.database import get_async_session
from app import models, schemas, security
from app.models import Category, Product, User
from app.schemas import UserCreate
from app.security import verify_password
import bcrypt
from fastapi import FastAPI, Response
from itsdangerous import URLSafeSerializer
import os
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from itsdangerous import URLSafeSerializer
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.ext.asyncio import async_engine_from_config
from app.database import Base, async_session
application = FastAPI()
templates = Jinja2Templates(directory="app/templates", auto_reload=True)
application.mount("/static", StaticFiles(directory="app/static"), name="static")
SECRET_KEY = "secretkey"

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
        domain = "127.0.0.1"
    )
    return {"message": "CSRF token generated"}
# Эндпоинт авторизации (логин)
@application.post("/login")
async def login(
        user: schemas.UserLogin,
        db: AsyncSession = Depends(get_db)
):
    print("\n\n--- Начало эндпоинта /login ---")
    print(f"Полученные данные: email={user.email}, пароль=******")

    print("Поиск пользователя в базе...")
    db_user = await authenticate_user(db, user.email, user.password)

    if not db_user:
        print(f"❌ Пользователь {user.email} не найден или неверный пароль")
        raise HTTPException(status_code=400, detail="Неверный email или пароль")

    print(f"✅ Пользователь {db_user.email} аутентифицирован")
    access_token = security.create_access_token(data={"sub": db_user.email})
    print(f"JWT-токен создан: {access_token}")
    return {"access_token": access_token, "token_type": "bearer"}



# Страница логина
@application.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


# Эндпоинт регистрации
@application.post("/register", response_model=schemas.Token)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
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
        password=user.password,  # Хеширование на уровне базы данных
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
    return {"access_token": access_token, "token_type": "bearer"}

@application.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})
# Главная страница
@application.get("/")
async def index(request: Request, db: AsyncSession = Depends(get_db)):
    try:
        result = await db.execute(select(models.Category))
        categories = result.scalars().all()
        return templates.TemplateResponse("index.html", {"request": request, "categories": categories})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {e}")


# Страница категории
@application.get("/category/{category_id}")
async def category_detail(request: Request, category_id: int, db: AsyncSession = Depends(get_async_session)):
    # Не вызываем db(), просто используем db
    result = await db.execute(select(Category).filter(Category.category_id == category_id))
    category = result.scalars().first()

    if category is None:
        return {"message": "Category not found"}

    # Получаем все продукты этой категории
    result = await db.execute(select(Product).filter(Product.category_id == category_id))
    products = result.scalars().all()

    return templates.TemplateResponse("category.html", {
        "request": request,
        "category": category,
        "products": products
    })


# Тест соединения с базой данных
@application.get("/test-db-connection")
async def test_db_connection(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute("SELECT 1")
        return {"status": "DB Connection Successful"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB Error: {e}")
