import os
import sqlite3
import hashlib
from datetime import datetime
from typing import Optional, Generator
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

DB_NAME = "fastdlc.db"

app = FastAPI(title="FastDLC Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                login TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                sub TEXT DEFAULT 'Нет подписки',
                sub_exp TEXT DEFAULT '—',
                hwid TEXT DEFAULT 'Не привязан',
                avatar TEXT DEFAULT ''
            )
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS chat (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT NOT NULL,
                avatar TEXT,
                sub TEXT,
                text TEXT NOT NULL,
                time TEXT NOT NULL
            )
            """
        )
        conn.commit()

init_db()

# Зависимость для безопасной работы с SQLite в многопоточной среде FastAPI
def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def hash_pw(pw: str) -> str:
    # При необходимости добавьте статическую или динамическую соль: (pw + "SALT").encode()
    return hashlib.sha256(pw.encode()).hexdigest()

# --- Pydantic Схемы ---
class AuthModel(BaseModel):
    login: str
    password: str
    action: str
    initData: Optional[str] = ""

class ChatMsg(BaseModel):
    login: str
    avatar: Optional[str] = ""
    sub: Optional[str] = "Гость"
    text: str

class KeyModel(BaseModel):
    login: str
    key: str

class ResetHwid(BaseModel):
    login: str

class AvatarModel(BaseModel):
    login: str
    avatar: str

# --- Эндпоинты ---
@app.get("/")
def root():
    return {"status": "ok", "service": "FastDLC Backend"}

@app.post("/api/auth")
def api_auth(data: AuthModel, db: sqlite3.Connection = Depends(get_db)):
    login = data.login.strip()
    pw_hash = hash_pw(data.password)
    cursor = db.cursor()

    if data.action == "register":
        cursor.execute("SELECT login FROM users WHERE login = ?", (login,))
        if cursor.fetchone():
            return {"ok": False, "error": "Логин уже занят!"}

        new_hwid = "HWID-" + os.urandom(4).hex().upper()
        cursor.execute(
            "INSERT INTO users (login, password_hash, hwid) VALUES (?, ?, ?)",
            (login, pw_hash, new_hwid)
        )
        db.commit()

    cursor.execute(
        "SELECT login, sub, sub_exp, hwid, avatar, password_hash FROM users WHERE login = ?", 
        (login,)
    )
    user = cursor.fetchone()
    
    if not user or user["password_hash"] != pw_hash:
        return {"ok": False, "error": "Неверный логин или пароль!"}

    return {
        "ok": True,
        "profile": {
            "login": user["login"],
            "sub": user["sub"],
            "sub_exp": user["sub_exp"],
            "hwid": user["hwid"],
            "avatar": user["avatar"]
        }
    }

@app.get("/api/chat")
def get_chat(db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT login, avatar, sub, text, time FROM chat ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    msgs = [
        {
            "login": r["login"],
            "avatar": r["avatar"],
            "sub": r["sub"],
            "text": r["text"],
            "time": r["time"]
        } 
        for r in reversed(rows)
    ]
    return {"ok": True, "messages": msgs}

@app.post("/api/chat")
def post_chat(msg: ChatMsg, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    time_str = datetime.now().strftime("%H:%M")
    cursor.execute(
        "INSERT INTO chat (login, avatar, sub, text, time) VALUES (?, ?, ?, ?, ?)",
        (msg.login, msg.avatar, msg.sub, msg.text, time_str)
    )
    db.commit()
    return {"ok": True}

@app.post("/api/activate_key")
def activate_key(data: KeyModel, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    
    cursor.execute("SELECT login FROM users WHERE login = ?", (data.login,))
    if not cursor.fetchone():
        return {"ok": False, "error": "Пользователь не найден"}

    # Пример проверки ключа и обновления записи
    sub_title = "Навсегда (Lifetime)"
    sub_exp = "Бессрочно"
    
    cursor.execute(
        "UPDATE users SET sub = ?, sub_exp = ? WHERE login = ?",
        (sub_title, sub_exp, data.login)
    )
    db.commit()
    return {"ok": True, "sub": sub_title, "sub_exp": sub_exp}

@app.post("/api/reset_hwid")
def reset_hwid(data: ResetHwid, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    new_hwid = "HWID-" + os.urandom(4).hex().upper()
    cursor.execute("UPDATE users SET hwid = ? WHERE login = ?", (new_hwid, data.login))
    db.commit()
    return {"ok": True, "hwid": new_hwid}

@app.post("/api/update_avatar")
def update_avatar(data: AvatarModel, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("UPDATE users SET avatar = ? WHERE login = ?", (data.avatar, data.login))
    db.commit()
    return {"ok": True}
