from fastapi import FastAPI, Depends, HTTPException
from sqlmodel import Session, select
from contextlib import asynccontextmanager
from database import create_db, get_session
from models import User
from passlib.context import CryptContext
import jwt
import time

SECRET_KEY = "SUPER_SECRET_KEY"
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_token(data: dict):
    data["exp"] = int(time.time()) + 3600
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Server Started")
    create_db()
    yield
    print("❌ Server Stopped")

app = FastAPI(lifespan=lifespan)

@app.get("/")
def home():
    return {"message": "API WORKING 🔥"}

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
