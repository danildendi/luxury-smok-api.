import os, json, secrets, hashlib, smtplib, statistics, time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
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
    if firebase_admin._apps:
        return
    raw = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON")
    if not raw:
        raise RuntimeError("Falta FIREBASE_SERVICE_ACCOUNT_JSON")
    cred = credentials.Certificate(json.loads(raw))
    firebase_admin.initialize_app(cred, {
        "databaseURL": os.environ["FIREBASE_DATABASE_URL"]
    })

init_firebase()
app = FastAPI(title=APP_NAME, version="1.0.0")
origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "").split(",") if x.strip()]
app.add_middleware(
    CORSMiddleware, allow_origins=origins or [],
    allow_credentials=False, allow_methods=["GET","POST","OPTIONS"],
    allow_headers=["Authorization","Content-Type"]
)

def users_ref():
    return db.reference("luxurysmok_auth/users")

def otp_ref():
    return db.reference("luxurysmok_auth/password_reset")

def send_email(to_email: str, subject: str, body: str):
    host = os.environ["SMTP_HOST"]
    port = int(os.getenv("SMTP_PORT", "587"))
    sender = os.environ["SMTP_USER"]
    password = os.environ["SMTP_APP_PASSWORD"]
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.getenv("SMTP_FROM", sender)
    msg["To"] = to_email
    msg.set_content(body)
    with smtplib.SMTP(host, port, timeout=20) as server:
        server.starttls()
        server.login(sender, password)
        server.send_message(msg)

def seed_user(username, role, initial_password, email):
    if not initial_password or not email:
        raise RuntimeError(f"Falta contraseña inicial o correo para {username}")
    ref = users_ref().child(username)
    existing = ref.get()
    if not existing:
        ref.set({
            "username": username, "role": role,
            "password_hash": pwd.hash(initial_password),
            "email": email.lower(), "active": True,
            "created_at": datetime.now(timezone.utc).isoformat()
        })

@app.on_event("startup")
def startup():
    # Crea estas cuentas solo si todavía no existen; nunca sobrescribe contraseñas.
    seed_user("admin", "admin", os.getenv("ADMIN_INITIAL_PASSWORD"), os.getenv("ADMIN_EMAIL"))
    seed_user("almacen", "almacenero", os.getenv("WAREHOUSE_INITIAL_PASSWORD"), os.getenv("WAREHOUSE_EMAIL"))

class LoginIn(BaseModel):
    username: str = Field(min_length=2, max_length=40)
    password: str = Field(min_length=1, max_length=128)

class ResetRequest(BaseModel):
    username: str = Field(min_length=2, max_length=40)

class ResetConfirm(BaseModel):
    username: str = Field(min_length=2, max_length=40)
    code: str = Field(min_length=6, max_length=6)
    new_password: str = Field(min_length=8, max_length=128)

class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=1500)

def get_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    if not credentials:
        raise HTTPException(401, "Sesión requerida")
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
        user = users_ref().child(username).get()
        if not user or not user.get("active"):
            raise HTTPException(401, "Cuenta inactiva")
        return user
    except JWTError:
        raise HTTPException(401, "Sesión inválida o vencida")

@app.get("/health")
def health():
    return {"status": "ok", "service": APP_NAME}

@app.post("/auth/login")
def login(data: LoginIn):
    user = users_ref().child(data.username).get()
    if not user or not user.get("active") or not pwd.verify(data.password, user["password_hash"]):
        raise HTTPException(401, "Usuario o contraseña incorrectos")
    token = jwt.encode({
        "sub": data.username,
        "role": user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_MINUTES)
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer",
            "user": {"username": user["username"], "role": user["role"]}}

@app.post("/auth/password-reset/request")
def request_reset(data: ResetRequest):
    user = users_ref().child(data.username).get()
    # Respuesta genérica para no revelar si existe el usuario.
    if user and user.get("active") and user.get("email"):
        code = f"{secrets.randbelow(1000000):06d}"
        salt = secrets.token_hex(16)
        digest = hashlib.sha256((salt + code).encode()).hexdigest()
        otp_ref().child(data.username).set({
            "salt": salt, "code_hash": digest,
            "expires_at": int(time.time()) + 600,
            "attempts": 0
        })
        send_email(user["email"], "Código de recuperación - Luxury Smok",
                   f"Tu código OTP es: {code}\n\nVence en 10 minutos. Si no solicitaste este cambio, ignora este correo.")
    return {"message": "Si la cuenta existe y tiene correo registrado, enviaremos un código de recuperación."}

@app.post("/auth/password-reset/confirm")
def confirm_reset(data: ResetConfirm):
    ref = otp_ref().child(data.username)
    record = ref.get()
    if not record or int(record.get("expires_at", 0)) < int(time.time()):
        raise HTTPException(400, "Código vencido o no solicitado")
    attempts = int(record.get("attempts", 0))
    if attempts >= 5:
        ref.delete()
        raise HTTPException(429, "Demasiados intentos. Solicita otro código.")
    digest = hashlib.sha256((record["salt"] + data.code).encode()).hexdigest()
    if not secrets.compare_digest(digest, record["code_hash"]):
        ref.child("attempts").set(attempts + 1)
        raise HTTPException(400, "Código incorrecto")
    users_ref().child(data.username).update({"password_hash": pwd.hash(data.new_password)})
    ref.delete()
    return {"message": "Contraseña actualizada correctamente"}

def get_stock_snapshot():
    data = db.reference("luxurysmok").get() or {}
    return data

@app.post("/ai/chat")
def ai_chat(data: ChatIn, user=Depends(get_user)):
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        raise HTTPException(503, "Falta configurar OPENAI_API_KEY en Render")
    stock = get_stock_snapshot()
    inv = stock.get("inv", [])
    ents = stock.get("ents", [])
    sals = stock.get("sals", [])
    # Solo se comparte un resumen operativo; no se envían fotos, DNI, PIN ni datos personales.
    context = {
        "inventory": [{"name": p.get("n"), "category": p.get("cat"),
                       "stock": p.get("st"), "minimum": p.get("min")} for p in inv],
        "recent_entries": [{"product": x.get("p"), "quantity": x.get("c"), "date": x.get("f")} for x in ents[-30:]],
        "recent_outputs": [{"product": x.get("p"), "quantity": x.get("c"), "date": x.get("f")} for x in sals[-30:]]
    }
    client = OpenAI(api_key=key)
    response = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        messages=[
            {"role":"system","content":"Eres el asistente interno de Luxury Smok. Responde en español, claro y breve. Basa los datos en el contexto JSON. No inventes cifras. Las salidas de almacén son movimientos de salida y no necesariamente ventas cobradas."},
            {"role":"user","content":"Datos operativos:\n"+json.dumps(context, ensure_ascii=False)+"\n\nConsulta: "+data.message}
        ],
        temperature=0.2
    )
    return {"answer": response.choices[0].message.content}

@app.get("/analytics/forecast")
def forecast(user=Depends(get_user)):
    data = get_stock_snapshot()
    inv = data.get("inv", [])
    outs = data.get("sals", [])
    # Proxy de demanda: total de salidas por producto en ventanas semanales.
    by_product = {}
    for item in outs:
        name = item.get("p")
        try:
            qty = float(item.get("c", 0))
        except (TypeError, ValueError):
            continue
        if name and qty > 0:
            by_product[name] = by_product.get(name, 0) + qty
    rows = []
    for p in inv:
        name = p.get("n")
        total = by_product.get(name, 0)
        # Promedio simple por semanas observadas; limita estimación para evitar exageraciones.
        weeks = max(1, min(4, len(outs) / 7))
        expected = round(total / weeks)
        if name:
            rows.append({"product": name, "current_stock": p.get("st", 0),
                         "expected_units": max(0, expected),
                         "basis": "salidas históricas; estimación orientativa"})
    rows.sort(key=lambda x: x["expected_units"], reverse=True)
    return {"method":"promedio simple de movimientos de salida",
            "warning":"El sistema actual registra salidas de almacén, no importe ni confirmación de ventas. Esta es una aproximación de demanda.",
            "forecast": rows[:20]}

@app.get("/analytics/synthetic-data")
def synthetic_data(days: int = 30, user=Depends(get_user)):
    if days < 1 or days > 180:
        raise HTTPException(400, "days debe estar entre 1 y 180")
    # Datos sintéticos solo para pruebas: no se escriben en Firebase.
    rng = secrets.SystemRandom()
    sample_products = ["Producto demostración A", "Producto demostración B", "Producto demostración C"]
    result = []
    today = datetime.now(timezone.utc).date()
    for offset in range(days):
        date = today - timedelta(days=days-offset-1)
        result.append({
            "date": date.isoformat(),
            "product": rng.choice(sample_products),
            "units_out": rng.randint(0, 12),
            "synthetic": True
        })
    return {"notice":"Datos ficticios de prueba; no se guardaron en Firebase.", "records":result}
