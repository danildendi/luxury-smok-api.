import os
import json
import secrets
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from typing import Optional

import firebase_admin
from firebase_admin import credentials, db

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jose import jwt, JWTError
from openai import OpenAI

APP_NAME = "Luxury Smok API"
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = "HS256"
JWT_MINUTES = int(os.getenv("JWT_MINUTES", "480"))

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer(auto_error=False)

def init_firebase():
    if firebase_admin._apps: return
    raw = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")
    if not raw: raise RuntimeError("Falta FIREBASE_SERVICE_ACCOUNT_JSON")
    cred = credentials.Certificate(json.loads(raw))
    firebase_admin.initialize_app(cred, {"databaseURL": os.environ["FIREBASE_DATABASE_URL"]})

init_firebase()
app = FastAPI(title=APP_NAME, version="1.0.0")

# ============ CONFIGURACIÓN CORS CORREGIDA ============
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://danildendi.github.io"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def users_ref(): return db.reference("luxurysmok_auth/users")
def otp_ref(): return db.reference("luxurysmok_auth/password_reset")

def find_user(identifier):
    identifier = identifier.strip().lower()
    users = users_ref().get() or {}
    for key, user in users.items():
        if not isinstance(user, dict): continue
        if (str(key).lower() == identifier or str(user.get("username", "")).lower() == identifier or str(user.get("email", "")).lower() == identifier):
            return key, user
    return None, None

def send_email(to_email: str, subject: str, body: str):
    api_key = os.environ.get("BREVO_API_KEY")
    sender_email = os.environ.get("BREVO_SENDER_EMAIL")
    payload = {
        "sender": {"name": "Luxury Smok", "email": sender_email},
        "to": [{"email": to_email}],
        "subject": subject,
        "textContent": body
    }
    req = urllib.request.Request("https://api.brevo.com/v3/smtp/email", data=json.dumps(payload).encode("utf-8"), headers={"api-key": api_key, "Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as response: return response.read().decode("utf-8")

def seed_user(username, role, initial_password, email):
    if not initial_password or not email: return
    ref = users_ref().child(username)
    if not ref.get():
        ref.set({"username": username, "role": role, "password_hash": pwd.hash(initial_password), "email": email.lower(), "active": True, "created_at": datetime.now(timezone.utc).isoformat()})

@app.on_event("startup")
def startup():
    seed_user("admin", "admin", os.getenv("ADMIN_INITIAL_PASSWORD"), os.getenv("ADMIN_EMAIL"))
    seed_user("almacen", "almacenero", os.getenv("WAREHOUSE_INITIAL_PASSWORD"), os.getenv("WAREHOUSE_EMAIL"))

class LoginIn(BaseModel):
    username: str = Field(min_length=2, max_length=254)
    password: str = Field(min_length=1, max_length=128)

class ResetRequest(BaseModel):
    username: str = Field(min_length=2, max_length=254)

class ResetConfirm(BaseModel):
    username: str = Field(min_length=2, max_length=254)
    code: str = Field(min_length=6, max_length=6)
    new_password: str = Field(min_length=8, max_length=128)

class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=1500)

def get_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    if not credentials: raise HTTPException(401, "Sesión requerida")
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        user_key, user = find_user(username)
        if not user or not user.get("active"): raise HTTPException(401, "Cuenta inactiva")
        return user
    except JWTError:
        raise HTTPException(401, "Sesión inválida o vencida")

@app.get("/health")
def health(): return {"status": "ok", "service": APP_NAME}

@app.post("/auth/login")
def login(data: LoginIn):
    user_key, user = find_user(data.username)
    if (not user or not user.get("active") or not pwd.verify(data.password, user["password_hash"])): raise HTTPException(401, "Usuario o contraseña incorrectos")
    token = jwt.encode({"sub": user_key, "role": user["role"], "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_MINUTES)}, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "user": {"username": user["username"], "role": user["role"]}}

@app.post("/auth/password-reset/request")
def request_reset(data: ResetRequest):
    user_key, user = find_user(data.username)
    if user and user.get("active") and user.get("email"):
        code = f"{secrets.randbelow(1000000):06d}"
        salt = secrets.token_hex(16)
        digest = hashlib.sha256((salt + code).encode()).hexdigest()
        otp_ref().child(user_key).set({"salt": salt, "code_hash": digest, "expires_at": int(time.time()) + 600, "attempts": 0})
        send_email(user["email"], "Código - Luxury Smok", f"Tu código OTP es: {code}")
    return {"message": "Si la cuenta existe, enviaremos un código."}

@app.post("/auth/password-reset/confirm")
def confirm_reset(data: ResetConfirm):
    user_key, user = find_user(data.username)
    if not user: raise HTTPException(400, "Error")
    ref = otp_ref().child(user_key)
    record = ref.get()
    if (not record or int(record.get("expires_at", 0)) < int(time.time())): raise HTTPException(400, "Código vencido")
    digest = hashlib.sha256((record["salt"] + data.code).encode()).hexdigest()
    if not secrets.compare_digest(digest, record["code_hash"]): raise HTTPException(400, "Código incorrecto")
    users_ref().child(user_key).update({"password_hash": pwd.hash(data.new_password)})
    ref.delete()
    return {"message": "Contraseña actualizada"}

@app.post("/ai/chat")
def ai_chat(data: ChatIn, user=Depends(get_user)):
    key = os.environ.get("OPENAI_API_KEY")
    if not key: raise HTTPException(503, "Falta API KEY")
    
    stock = db.reference("luxurysmok").get() or {}
    inv = stock.get("inv", [])
    
    context = {"inventory": [{"name": p.get("n"), "stock": p.get("st")} for p in inv]}
    
    client = OpenAI(base_url="https://api.groq.com/openai/v1", api_key=key)
    response = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "llama-3.3-70b-versatile"),
        messages=[
            {"role": "system", "content": "Eres el asistente de Luxury Smok. Responde breve en español basándote en los datos JSON."},
            {"role": "user", "content": f"Datos: {json.dumps(context)}\n\nPregunta: {data.message}"}
        ],
        temperature=0.2
    )
    return {"answer": response.choices[0].message.content}
