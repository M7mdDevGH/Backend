from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlmodel import Session, select
from contextlib import asynccontextmanager
from database import create_db, get_session
from models import User
from passlib.context import CryptContext
import jwt
import time

# 🔐 CONFIG
SECRET_KEY = "SUPER_SECRET_KEY"
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 🧠 Rate limit (simple)
requests_log = {}

# 🔑 Password
def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

# 🔐 JWT
def create_token(data: dict):
    data["exp"] = int(time.time()) + 3600
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# 🚀 Lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Server Started")
    create_db()
    yield
    print("❌ Server Stopped")

app = FastAPI(lifespan=lifespan)

# =========================
# 🔥 Middleware
# =========================

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()

    # 🛑 Rate limit (10 requests / 10 sec)
    ip = request.client.host
    now = time.time()

    if ip not in requests_log:
        requests_log[ip] = []

    requests_log[ip] = [t for t in requests_log[ip] if now - t < 10]

    if len(requests_log[ip]) > 10:
        return JSONResponse(
            status_code=429,
            content={"error": "Too many requests 🚫"}
        )

    requests_log[ip].append(now)

    response = await call_next(request)

    process_time = time.time() - start_time
    print(f"{request.method} {request.url} - {process_time:.3f}s")

    # 🔐 Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    return response

# =========================
# 🌐 ROUTES
# =========================

@app.get("/")
def home():
    return {"message": "SECURE API 🔐🔥"}

@app.post("/register")
def register(username: str, password: str, session: Session = Depends(get_session)):
    user = User(username=username, password=hash_password(password))
    session.add(user)
    session.commit()
    return {"message": "User created"}

@app.post("/login")
def login(username: str, password: str, session: Session = Depends(get_session)):
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()

    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_token({"user_id": user.id})
    return {"token": token}