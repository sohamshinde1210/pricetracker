from __future__ import annotations
from fastapi import FastAPI, Request, Form, Depends, Response, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, String, select, Float, Integer, DateTime, Text, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session, relationship
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
import os
import shutil
import httpx
from bs4 import BeautifulSoup
from typing import Optional, List
import json
import random

# ==========================================
# 1. SECURITY & JWT CONFIGURATION
# ==========================================
SECRET_KEY = "my_super_secret_key_for_development"  # In production, keep this safe!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# ==========================================
# UPLOAD FOLDER SETUP
# ==========================================

UPLOAD_DIR = "static/uploads"

# If uploads exists but is a file, remove it
if os.path.exists(UPLOAD_DIR) and not os.path.isdir(UPLOAD_DIR):
    os.remove(UPLOAD_DIR)

# Create uploads folder if it doesn't exist
os.makedirs(UPLOAD_DIR, exist_ok=True)

print("UPLOAD_DIR:", UPLOAD_DIR)
print("EXISTS:", os.path.exists(UPLOAD_DIR))
print("IS DIRECTORY:", os.path.isdir(UPLOAD_DIR))


def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode("utf-8")[:72], hashed_password.encode("utf-8"))


def get_password_hash(password):
    return bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ==========================================
# 2. DATABASE SETUP
# ==========================================
engine = create_engine("sqlite:///price_tracker.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    email: Mapped[str] = mapped_column(String(100), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    products: Mapped[List["TrackedProduct"]] = relationship("TrackedProduct", back_populates="owner")


class TrackedProduct(Base):
    __tablename__ = "tracked_products"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(200))
    category: Mapped[str] = mapped_column(String(100))
    our_price: Mapped[float] = mapped_column(Float)
    alert_threshold: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    image_path: Mapped[Optional[str]] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    owner: Mapped["User"] = relationship("User", back_populates="products")
    competitors: Mapped[List["CompetitorPrice"]] = relationship("CompetitorPrice", back_populates="product", cascade="all, delete-orphan")
    price_history: Mapped[List["PriceHistory"]] = relationship("PriceHistory", back_populates="product", cascade="all, delete-orphan")


class CompetitorPrice(Base):
    __tablename__ = "competitor_prices"
    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("tracked_products.id"))
    competitor_name: Mapped[str] = mapped_column(String(200))
    competitor_url: Mapped[str] = mapped_column(String(500))
    current_price: Mapped[float] = mapped_column(Float)
    last_checked: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    product: Mapped["TrackedProduct"] = relationship("TrackedProduct", back_populates="competitors")


class PriceHistory(Base):
    __tablename__ = "price_history"
    id: Mapped[int] = mapped_column(primary_key=True)
    product_id: Mapped[int] = mapped_column(ForeignKey("tracked_products.id"))
    source: Mapped[str] = mapped_column(String(200))  # "us" or competitor name
    price: Mapped[float] = mapped_column(Float)
    recorded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    product: Mapped["TrackedProduct"] = relationship("TrackedProduct", back_populates="price_history")


class PriceAlert(Base):
    __tablename__ = "price_alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    product_id: Mapped[int] = mapped_column(ForeignKey("tracked_products.id"))
    message: Mapped[str] = mapped_column(Text)
    is_read: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)

# ==========================================
# 3. FASTAPI SETUP & DEPENDENCIES
# ==========================================
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="Frontend")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
    except jwt.InvalidTokenError:
        return None
    user = db.scalars(select(User).where(User.email == email)).first()
    return user


# ==========================================
# 4. AUTHENTICATION ROUTES
# ==========================================

@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    return templates.TemplateResponse(request=request, name="signup.html")


@app.post("/signup")
def signup_post(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    existing = db.scalars(select(User).where(User.email == email)).first()
    if existing:
        return templates.TemplateResponse(
            request=request, name="signup.html", context={"error": "Email already registered."}
        )
    new_user = User(name=name, email=email, hashed_password=get_password_hash(password))
    db.add(new_user)
    db.commit()
    token = create_access_token(data={"sub": new_user.email})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=token, httponly=True, max_age=86400)
    return response


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")


@app.post("/login")
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.scalars(select(User).where(User.email == email)).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse(
            request=request, name="login.html", context={"error": "Invalid email or password."}
        )
    token = create_access_token(data={"sub": user.email})
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(key="access_token", value=token, httponly=True, max_age=86400)
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response


# ==========================================
# 5. DASHBOARD & PRODUCT ROUTES
# ==========================================

@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    products = db.scalars(
        select(TrackedProduct).where(TrackedProduct.user_id == current_user.id)
    ).all()

    unread_alerts = db.scalars(
        select(PriceAlert).where(
            PriceAlert.user_id == current_user.id,
            PriceAlert.is_read == False,
        )
    ).all()

    # Stats
    total_products = len(products)
    cheaper_count = 0
    saving_opportunities = 0

    for p in products:
        if p.competitors:
            min_comp = min(c.current_price for c in p.competitors)
            if min_comp < p.our_price:
                cheaper_count += 1
                saving_opportunities += 1

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "products": products,
            "current_user": current_user,
            "unread_alerts": unread_alerts,
            "total_products": total_products,
            "cheaper_count": cheaper_count,
            "saving_opportunities": saving_opportunities,
        },
    )


@app.get("/product/{product_id}", response_class=HTMLResponse)
def product_detail(
    request: Request,
    product_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    product = db.get(TrackedProduct, product_id)
    if not product or product.user_id != current_user.id:
        return RedirectResponse(url="/", status_code=303)

    # Build price history JSON for chart
    history_data = {}
    for h in sorted(product.price_history, key=lambda x: x.recorded_at):
        src = h.source
        if src not in history_data:
            history_data[src] = []
        history_data[src].append(
            {"date": h.recorded_at.strftime("%b %d"), "price": h.price}
        )

    return templates.TemplateResponse(
        request=request,
        name="product_detail.html",
        context={
            "product": product,
            "current_user": current_user,
            "history_json": json.dumps(history_data),
        },
    )


@app.get("/create", response_class=HTMLResponse)
def create_page(request: Request, current_user: User = Depends(get_current_user)):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request=request, name="create.html")


@app.post("/create")
async def create_product(
    name: str = Form(...),
    category: str = Form(...),
    our_price: float = Form(...),
    alert_threshold: Optional[float] = Form(None),
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    image_path = None
    if image and image.filename:
        ext = os.path.splitext(image.filename)[1]
        fname = f"{datetime.now().timestamp()}{ext}"
        image_path = f"uploads/{fname}"
        with open(os.path.join(UPLOAD_DIR, fname), "wb") as buf:
            shutil.copyfileobj(image.file, buf)

    product = TrackedProduct(
        user_id=current_user.id,
        name=name,
        category=category,
        our_price=our_price,
        alert_threshold=alert_threshold,
        image_path=image_path,
    )
    db.add(product)
    db.commit()

    # Record initial price history
    db.add(PriceHistory(product_id=product.id, source="Our Price", price=our_price))
    db.commit()

    return RedirectResponse(url="/", status_code=303)


@app.get("/update/{product_id}", response_class=HTMLResponse)
def update_page(
    request: Request,
    product_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    product = db.get(TrackedProduct, product_id)
    return templates.TemplateResponse(
        request=request, name="update.html", context={"product": product}
    )


@app.post("/update/{product_id}")
async def update_product(
    product_id: int,
    name: str = Form(...),
    category: str = Form(...),
    our_price: float = Form(...),
    alert_threshold: Optional[float] = Form(None),
    image: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    product = db.get(TrackedProduct, product_id)
    if product and product.user_id == current_user.id:
        old_price = product.our_price
        product.name = name
        product.category = category
        product.our_price = our_price
        product.alert_threshold = alert_threshold

        if image and image.filename:
            if product.image_path:
                old = os.path.join("static", product.image_path)
                if os.path.exists(old):
                    os.remove(old)
            ext = os.path.splitext(image.filename)[1]
            fname = f"{datetime.now().timestamp()}{ext}"
            product.image_path = f"uploads/{fname}"
            with open(os.path.join(UPLOAD_DIR, fname), "wb") as buf:
                shutil.copyfileobj(image.file, buf)

        # Record price change
        if old_price != our_price:
            db.add(PriceHistory(product_id=product.id, source="Our Price", price=our_price))

        db.commit()
    return RedirectResponse(url="/", status_code=303)


@app.get("/delete/{product_id}")
def delete_product(
    product_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    product = db.get(TrackedProduct, product_id)
    if product and product.user_id == current_user.id:
        if product.image_path:
            old = os.path.join("static", product.image_path)
            if os.path.exists(old):
                os.remove(old)
        db.delete(product)
        db.commit()
    return RedirectResponse(url="/", status_code=303)


# ==========================================
# 6. COMPETITOR PRICE ROUTES
# ==========================================

@app.post("/product/{product_id}/competitor/add")
async def add_competitor(
    product_id: int,
    competitor_name: str = Form(...),
    competitor_url: str = Form(...),
    current_price: float = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    product = db.get(TrackedProduct, product_id)
    if not product or product.user_id != current_user.id:
        return RedirectResponse(url="/", status_code=303)

    competitor = CompetitorPrice(
        product_id=product_id,
        competitor_name=competitor_name,
        competitor_url=competitor_url,
        current_price=current_price,
    )
    db.add(competitor)

    # Record in history
    db.add(PriceHistory(product_id=product_id, source=competitor_name, price=current_price))

    # Check alert threshold
    if product.alert_threshold and current_price <= product.alert_threshold:
        alert = PriceAlert(
            user_id=current_user.id,
            product_id=product_id,
            message=f"🔔 {competitor_name} is offering '{product.name}' at ${current_price:.2f} — at or below your alert threshold of ${product.alert_threshold:.2f}!",
        )
        db.add(alert)

    db.commit()
    return RedirectResponse(url=f"/product/{product_id}", status_code=303)


@app.post("/competitor/{competitor_id}/update")
async def update_competitor_price(
    competitor_id: int,
    new_price: float = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)

    comp = db.get(CompetitorPrice, competitor_id)
    if not comp:
        return JSONResponse({"error": "Not found"}, status_code=404)

    product = db.get(TrackedProduct, comp.product_id)
    comp.current_price = new_price
    comp.last_checked = datetime.utcnow()

    db.add(PriceHistory(product_id=comp.product_id, source=comp.competitor_name, price=new_price))

    if product and product.alert_threshold and new_price <= product.alert_threshold:
        alert = PriceAlert(
            user_id=current_user.id,
            product_id=comp.product_id,
            message=f"🔔 {comp.competitor_name} updated '{product.name}' to ${new_price:.2f} — at or below your threshold of ${product.alert_threshold:.2f}!",
        )
        db.add(alert)

    db.commit()
    return RedirectResponse(url=f"/product/{comp.product_id}", status_code=303)


@app.get("/competitor/{competitor_id}/delete")
def delete_competitor(
    competitor_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)
    comp = db.get(CompetitorPrice, competitor_id)
    if comp:
        pid = comp.product_id
        db.delete(comp)
        db.commit()
        return RedirectResponse(url=f"/product/{pid}", status_code=303)
    return RedirectResponse(url="/", status_code=303)


# ==========================================
# 7. ALERTS ROUTES
# ==========================================

@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    alerts = db.scalars(
        select(PriceAlert)
        .where(PriceAlert.user_id == current_user.id)
        .order_by(PriceAlert.created_at.desc())
    ).all()

    # Mark all as read
    for a in alerts:
        a.is_read = True
    db.commit()

    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={"alerts": alerts, "current_user": current_user},
    )


@app.get("/api/alerts/unread-count")
def unread_count(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not current_user:
        return JSONResponse({"count": 0})
    count = len(
        db.scalars(
            select(PriceAlert).where(
                PriceAlert.user_id == current_user.id,
                PriceAlert.is_read == False,
            )
        ).all()
    )
    return JSONResponse({"count": count})


# ==========================================
# 8. SIMULATE PRICE SCRAPE (Demo)
# ==========================================

@app.post("/product/{product_id}/simulate-scrape")
def simulate_scrape(
    product_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Simulate a price scrape by randomly updating competitor prices (for demo)."""
    if not current_user:
        return RedirectResponse(url="/login", status_code=303)

    product = db.get(TrackedProduct, product_id)
    if not product or product.user_id != current_user.id:
        return RedirectResponse(url="/", status_code=303)

    for comp in product.competitors:
        # Simulate price fluctuation ±15%
        change = random.uniform(-0.15, 0.15)
        new_price = round(comp.current_price * (1 + change), 2)
        comp.current_price = new_price
        comp.last_checked = datetime.utcnow()
        db.add(PriceHistory(product_id=product_id, source=comp.competitor_name, price=new_price))

        if product.alert_threshold and new_price <= product.alert_threshold:
            db.add(
                PriceAlert(
                    user_id=current_user.id,
                    product_id=product_id,
                    message=f"🔔 {comp.competitor_name} is now offering '{product.name}' at ${new_price:.2f} — below your threshold of ${product.alert_threshold:.2f}!",
                )
            )

    db.commit()
    return RedirectResponse(url=f"/product/{product_id}", status_code=303)