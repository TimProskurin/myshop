# app/models.py
from sqlalchemy import Column, Integer, String, Text, Float, ForeignKey, DateTime, Enum, JSON
from sqlalchemy.orm import relationship
from app.database import Base  # Используем базовый класс для создания моделей
from sqlalchemy import Column, Integer, String
from app.database import Base
import enum
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, unique=True, index=True, nullable=False)
    address = Column(String, nullable=False)
    registration_date = Column(DateTime, nullable=False)
    password = Column(String, nullable=False)
    
    orders = relationship("Order", back_populates="user")
    logs = relationship("UserLog", back_populates="user", cascade="all, delete-orphan")


class Category(Base):
    __tablename__ = 'categories'

    category_id = Column(Integer, primary_key=True, index=True)
    category_name = Column(String, index=True)
    description = Column(Text)

    # Связь с продуктами
    products = relationship("Product", back_populates="category")


class Product(Base):
    __tablename__ = 'products'

    product_id = Column(Integer, primary_key=True, index=True)
    category_id = Column(Integer, ForeignKey('categories.category_id'))
    product_name = Column(String)
    description = Column(Text)
    price = Column(Float)
    stock = Column(Integer)
    created_at = Column(String)

    # Связь с категорией
    category = relationship("Category", back_populates="products")


class OrderStatus(enum.Enum):
    pending = "В обработке"
    completed = "Выполнен"
    cancelled = "Отменён"

class Order(Base):
    __tablename__ = "orders"

    order_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id"))
    total_amount = Column(Float, nullable=False)
    status = Column(String(50), nullable=False)
    order_date = Column(DateTime, nullable=False)
    address = Column(String(255), nullable=False)
    
    user = relationship("User", back_populates="orders")
    items = relationship("OrderItem", back_populates="order")

class OrderItem(Base):
    __tablename__ = "orderitems"

    order_item_id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, ForeignKey("orders.order_id"))
    product_id = Column(Integer, ForeignKey("products.product_id"))
    quantity = Column(Integer, nullable=False)
    
    order = relationship("Order", back_populates="items")
    product = relationship("Product")

class UserLog(Base):
    __tablename__ = "user_logs"

    log_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id", ondelete="CASCADE"))
    action = Column(String(50), nullable=False)
    old_data = Column(JSON)
    new_data = Column(JSON)
    changed_at = Column(DateTime, default=datetime.utcnow)

    # Связь с пользователем
    user = relationship("User", back_populates="logs")
