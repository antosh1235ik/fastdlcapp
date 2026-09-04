import sqlite3
from typing import List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=True,
    allow_methods=[],
    allow_headers=[],
)

pwd_context = CryptContext(schemes=[bcrypt], deprecated=auto)

# Инициализация базы данных SQLite
conn = sqlite3.connect(fastdlc.db, check_same_thread=False)
cursor = conn.cursor()
cursor.execute(
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
)
)
conn.commit()

class UserAuth(BaseModel)
    username str
    password str

@app.post(register)
def register(user UserAuth)
    username = user.username.strip()
    if len(username)  3 or len(user.password)  4
        raise HTTPException(status_code=400, detail=Слишком короткий логин или пароль)
    
    hashed = pwd_context.hash(user.password)
    try
        cursor.execute(INSERT INTO users (username, password_hash) VALUES (, ), (username, hashed))
        conn.commit()
        return {status ok, username username}
    except sqlite3.IntegrityError
        raise HTTPException(status_code=400, detail=Пользователь с таким ником уже существует)

@app.post(login)
def login(user UserAuth)
    username = user.username.strip()
    cursor.execute(SELECT password_hash FROM users WHERE username = , (username,))
    row = cursor.fetchone()
    if not row or not pwd_context.verify(user.password, row[0])
        raise HTTPException(status_code=400, detail=Неверный логин или пароль)
    return {status ok, username username}

# Менеджер WebSockets для общего чата
class ConnectionManager
    def __init__(self)
        self.active_connections List[WebSocket] = []

    async def connect(self, websocket WebSocket)
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket WebSocket)
        if websocket in self.active_connections
            self.active_connections.remove(websocket)

    async def broadcast(self, message str)
        for connection in self.active_connections
            try
                await connection.send_text(message)
            except Exception
                pass

manager = ConnectionManager()

@app.websocket(wschat)
async def websocket_endpoint(websocket WebSocket)
    await manager.connect(websocket)
    try
        while True
            data = await websocket.receive_text()
            await manager.broadcast(data)
    except WebSocketDisconnect
        manager.disconnect(websocket)