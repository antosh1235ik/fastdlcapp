import os
import hmac
import hashlib
import sqlite3
import json
from datetime import datetime, timedelta
from urllib.parse import parse_qsl
from flask import Flask, request, jsonify
from flask_cors import CORS

BOT_TOKEN = "8891306947:AAHD4tua2WjFyGbXzJQW9VZMFJXA3He0dHA"
DB_PATH = "fastdlc_system.db"

app = Flask(__name__)
CORS(app)

TARIFF_DAYS = {
    "week": ("1 Неделя", 7),
    "month": ("30 Дней", 30),
    "quarter": ("90 Дней", 90),
    "year": ("365 Дней", 365),
    "forever": ("Lifetime", 9999)
}

INITIAL_KEYS = {
    "week": [
        "FAST-9C4E0A72B", "FAST-3F1843399", "FAST-28562A86F", "FAST-A8DC106BE", "FAST-E691349D0",
        "FAST-4D6652433", "FAST-8722EB1A2", "FAST-C2F0DBF85", "FAST-CF5EB2875", "FAST-00C5BA228"
    ],
    "month": [
        "FAST-D2952B9EC", "FAST-313658514", "FAST-B9E404E2B", "FAST-309AE2C17", "FAST-5542DA63B"
    ],
    "quarter": [
        "FAST-D500C02DC", "FAST-309AE2C17", "FAST-5542DA63B", "FAST-374665809", "FAST-84AE9FF12"
    ],
    "year": [
        "FAST-D925F4C81", "FAST-B0A1C8E56", "FAST-C8D76E2A1", "FAST-35D8A9F1B", "FAST-4EF91B5C0"
    ],
    "forever": [
        "FAST-99A04B1EF", "FAST-F4E56BCFE", "FAST-D14B9A76A", "FAST-91060935B", "FAST-14D567676"
    ]
}

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Таблица пользователей
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        telegram_id INTEGER UNIQUE,
        username TEXT,
        login TEXT UNIQUE,
        password_hash TEXT,
        avatar_url TEXT DEFAULT '',
        hwid TEXT DEFAULT 'Не привязан',
        sub_status TEXT DEFAULT 'Нет подписки',
        sub_expires TEXT DEFAULT '—',
        registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    # Таблица ключей
    c.execute('''CREATE TABLE IF NOT EXISTS license_keys (
        key_code TEXT PRIMARY KEY,
        tier TEXT,
        is_used INTEGER DEFAULT 0,
        used_by TEXT
    )''')
    for tier, keys in INITIAL_KEYS.items():
        for k in keys:
            c.execute("INSERT OR IGNORE INTO license_keys (key_code, tier) VALUES (?, ?)", (k, tier))
            
    # Таблица чата
    c.execute('''CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_login TEXT,
        user_avatar TEXT,
        sub_status TEXT,
        message TEXT,
        created_at TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

def verify_tg(init_data: str):
    if not init_data:
        return None
    try:
        vals = dict(parse_qsl(init_data, keep_blank_values=True))
        hash_check = vals.pop('hash')
        data_check_string = '\n'.join(f"{k}={v}" for k, v in sorted(vals.items()))
        secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        calc_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        if calc_hash == hash_check:
            return json.loads(vals['user'])
    except Exception:
        pass
    return None

@app.route('/api/auth', methods=['POST'])
def auth():
    data = request.get_json(force=True)
    tg_user = verify_tg(data.get('initData', ''))
    login = data.get('login', '').strip()
    password = data.get('password', '').strip()
    action = data.get('action', 'login')

    if not login or not password:
        return jsonify({"ok": False, "error": "Заполните логин и пароль"}), 400

    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    tg_id = tg_user['id'] if tg_user else None
    tg_nick = tg_user.get('username', '') if tg_user else ''

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if action == 'register':
        c.execute("SELECT id FROM users WHERE login = ?", (login,))
        if c.fetchone():
            conn.close()
            return jsonify({"ok": False, "error": "Этот логин уже занят"}), 400

        c.execute('''INSERT INTO users (telegram_id, username, login, password_hash, hwid, sub_status, sub_expires)
                     VALUES (?, ?, ?, ?, 'Не привязан', 'Нет подписки', '—')''', 
                  (tg_id, tg_nick, login, pwd_hash))
        conn.commit()

    c.execute('''SELECT login, avatar_url, hwid, sub_status, sub_expires, password_hash 
                 FROM users WHERE login = ?''', (login,))
    user = c.fetchone()
    conn.close()

    # Если пользователя нет в базе ИЛИ пароль не совпал
    if not user or user[5] != pwd_hash:
        return jsonify({"ok": False, "error": "Неверный логин или пароль"}), 401

    return jsonify({
        "ok": True,
        "profile": {
            "login": user[0],
            "avatar": user[1],
            "hwid": user[2],
            "sub": user[3],
            "sub_exp": user[4]
        }
    })

@app.route('/api/activate_key', methods=['POST'])
def activate_key():
    data = request.get_json(force=True)
    login = data.get('login', '').strip()
    key = data.get('key', '').strip().upper()

    if not login or not key:
        return jsonify({"ok": False, "error": "Не указан логин или ключ"}), 400

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT tier, is_used FROM license_keys WHERE key_code = ?", (key,))
    key_row = c.fetchone()

    if not key_row:
        conn.close()
        return jsonify({"ok": False, "error": "Ключ не существует"}), 400

    if key_row[1] == 1:
        conn.close()
        return jsonify({"ok": False, "error": "Этот ключ уже активирован"}), 400

    tier = key_row[0]
    tier_name, days = TARIFF_DAYS.get(tier, ("Подписка", 30))

    if days > 9000:
        exp_date_str = "Бессрочно"
    else:
        exp_date = datetime.now() + timedelta(days=days)
        exp_date_str = exp_date.strftime("%d.%m.%Y")

    c.execute("UPDATE license_keys SET is_used = 1, used_by = ? WHERE key_code = ?", (login, key))
    c.execute("UPDATE users SET sub_status = ?, sub_expires = ? WHERE login = ?", (tier_name, exp_date_str, login))
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "sub": tier_name,
        "sub_exp": exp_date_str
    })

@app.route('/api/reset_hwid', methods=['POST'])
def reset_hwid():
    data = request.get_json(force=True)
    login = data.get('login', '').strip()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET hwid = 'Не привязан' WHERE login = ?", (login,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "hwid": "Не привязан"})

@app.route('/api/update_avatar', methods=['POST'])
def update_avatar():
    data = request.get_json(force=True)
    login = data.get('login', '')
    avatar = data.get('avatar', '')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET avatar_url = ? WHERE login = ?", (avatar, login))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.route('/api/chat', methods=['GET', 'POST'])
def chat():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if request.method == 'POST':
        data = request.get_json(force=True)
        login = data.get('login', 'Гость')
        avatar = data.get('avatar', '')
        sub = data.get('sub', 'Нет подписки')
        text = data.get('text', '').strip()

        if text:
            time_now = datetime.now().strftime("%H:%M")
            c.execute('''INSERT INTO chat_messages (user_login, user_avatar, sub_status, message, created_at)
                         VALUES (?, ?, ?, ?, ?)''', (login, avatar, sub, text, time_now))
            conn.commit()

    c.execute("SELECT user_login, user_avatar, sub_status, message, created_at FROM chat_messages ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()

    messages = [{
        "login": r[0],
        "avatar": r[1],
        "sub": r[2],
        "text": r[3],
        "time": r[4]
    } for r in reversed(rows)]

    return jsonify({"ok": True, "messages": messages})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)