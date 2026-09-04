import os
import sqlite3
import hashlib
from datetime import datetime
from typing import Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Инициализация базы данных
conn = sqlite3.connect("fastdlc.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute(
    "CREATE TABLE IF NOT EXISTS users ("
    "login TEXT PRIMARY KEY, "
    "password_hash TEXT, "
    "sub TEXT DEFAULT 'Нет подписки', "
    "sub_exp TEXT DEFAULT '—', "
    "hwid TEXT DEFAULT 'Не привязан', "
    "avatar TEXT DEFAULT ''"
    ")"
)

cursor.execute(
    "CREATE TABLE IF NOT EXISTS chat ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "login TEXT, "
    "avatar TEXT, "
    "sub TEXT, "
    "text TEXT, "
    "time TEXT"
    ")"
)
conn.commit()

def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

@app.get("/")
def root():
    return {"status": "ok", "service": "FastDLC Backend"}

class AuthModel(BaseModel):
    login: str
    password: str
    action: str
    initData: Optional[str] = ""

@app.post("/api/auth")
def api_auth(data: AuthModel):
    login = data.login.strip()
    pw_hash = hash_pw(data.password)

    if data.action == "register":
        cursor.execute("SELECT login FROM users WHERE login = ?", (login,))
        if cursor.fetchone():
            return {"ok": False, "error": "Логин уже занят!"}
        
        cursor.execute(
            "INSERT INTO users (login, password_hash, hwid) VALUES (?, ?, ?)",
            (login, pw_hash, "HWID-" + os.urandom(4).hex().upper())
        )
        conn.commit()

    cursor.execute("SELECT login, sub, sub_exp, hwid, avatar, password_hash FROM users WHERE login = ?", (login,))
    user = cursor.fetchone()
    if not user or user[5] != pw_hash:
        return {"ok": False, "error": "Неверный логин или пароль!"}

    return {
        "ok": True,
        "profile": {
            "login": user[0],
            "sub": user[1],
            "sub_exp": user[2],
            "hwid": user[3],
            "avatar": user[4]
        }
    }

@app.get("/api/chat")
def get_chat():
    cursor.execute("SELECT login, avatar, sub, text, time FROM chat ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    msgs = [{"login": r[0], "avatar": r[1], "sub": r[2], "text": r[3], "time": r[4]} for r in reversed(rows)]
    return {"ok": True, "messages": msgs}

class ChatMsg(BaseModel):
    login: str
    avatar: Optional[str] = ""
    sub: Optional[str] = "Гость"
    text: str

@app.post("/api/chat")
def post_chat(msg: ChatMsg):
    time_str = datetime.now().strftime("%H:%M")
    cursor.execute(
        "INSERT INTO chat (login, avatar, sub, text, time) VALUES (?, ?, ?, ?, ?)",
        (msg.login, msg.avatar, msg.sub, msg.text, time_str)
    )
    conn.commit()
    return {"ok": True}

class KeyModel(BaseModel):
    login: str
    key: str

@app.post("/api/activate_key")
def activate_key(data: KeyModel):
    return {"ok": True, "sub": "Навсегда (Lifetime)", "sub_exp": "Бессрочно"}

class ResetHwid(BaseModel):
    login: str

@app.post("/api/reset_hwid")
def reset_hwid(data: ResetHwid):
    new_hwid = "HWID-" + os.urandom(4).hex().upper()
    cursor.execute("UPDATE users SET hwid = ? WHERE login = ?", (new_hwid, data.login))
    conn.commit()
    return {"ok": True, "hwid": new_hwid}

class AvatarModel(BaseModel):
    login: str
    avatar: str

@app.post("/api/update_avatar")
def update_avatar(data: AvatarModel):
    cursor.execute("UPDATE users SET avatar = ? WHERE login = ?", (data.avatar, data.login))
    conn.commit()
    return {"ok": True}
