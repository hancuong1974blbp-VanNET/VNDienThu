# -*- coding: utf-8 -*-
"""
VNThư - Máy chủ (server) cho web email tiếng Việt.
Chạy thật: đăng ký / đăng nhập, gửi thư, đính kèm file tối đa 1GB.
Lưu trữ bằng SQLite + file trên đĩa (không dùng base64 trong trình duyệt).

Cách chạy:
    pip install flask
    python server.py
Sau đó mở trình duyệt vào:  http://127.0.0.1:5000
"""
import os
import sqlite3
import hashlib
import secrets
import time
import mimetypes
from flask import Flask, request, jsonify, send_file, send_from_directory, g, abort

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vnthu.db")
FILES_DIR = os.path.join(BASE_DIR, "attachments")
MAX_FILE = 1024 * 1024 * 1024  # 1 GB

os.makedirs(FILES_DIR, exist_ok=True)

app = Flask(__name__, static_folder=None)
_DB_READY = False
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE + 32 * 1024 * 1024  # 1GB + lề cho form


# ----------------------------- Database -----------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            salt TEXT NOT NULL,
            pwd_hash TEXT NOT NULL,
            created REAL
        );
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created REAL
        );
        CREATE TABLE IF NOT EXISTS mails (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            subject TEXT,
            body TEXT,
            created REAL,
            read_flag INTEGER DEFAULT 0,
            deleted_by_sender INTEGER DEFAULT 0,
            deleted_by_recipient INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mail_id INTEGER NOT NULL,
            filename TEXT,
            stored TEXT,
            size INTEGER,
            mime TEXT
        );
        """
    )
    db.commit()
    db.close()


# ----------------------------- Auth helpers -----------------------------
def hash_pwd(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               bytes.fromhex(salt), 120000).hex()


def current_user():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip()
    if not token:
        token = request.args.get("token", "") or request.form.get("token", "")
    if not token:
        return None
    db = get_db()
    row = db.execute(
        "SELECT u.* FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.token=?",
        (token,),
    ).fetchone()
    return row


def require_user():
    u = current_user()
    if u is None:
        abort(401)
    return u


# ----------------------------- API: Auth -----------------------------
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    name = (data.get("name") or "").strip()
    pwd = data.get("password") or ""
    if not email or "@" not in email or len(pwd) < 4:
        return jsonify(error="Email hoặc mật khẩu không hợp lệ (mật khẩu >= 4 ký tự)."), 400
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        return jsonify(error="Email này đã được đăng ký."), 400
    salt = secrets.token_hex(16)
    db.execute(
        "INSERT INTO users(email,name,salt,pwd_hash,created) VALUES(?,?,?,?,?)",
        (email, name or email.split("@")[0], salt, hash_pwd(pwd, salt), time.time()),
    )
    db.commit()
    return _issue_token(email)


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    pwd = data.get("password") or ""
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not row or hash_pwd(pwd, row["salt"]) != row["pwd_hash"]:
        return jsonify(error="Sai email hoặc mật khẩu."), 401
    return _issue_token(email)


def _issue_token(email):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    token = secrets.token_hex(24)
    db.execute("INSERT INTO tokens(token,user_id,created) VALUES(?,?,?)",
               (token, row["id"], time.time()))
    db.commit()
    return jsonify(token=token, email=row["email"], name=row["name"])


@app.route("/api/me", methods=["GET"])
def api_me():
    u = require_user()
    return jsonify(email=u["email"], name=u["name"])


@app.route("/api/logout", methods=["POST"])
def api_logout():
    auth = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if auth:
        db = get_db()
        db.execute("DELETE FROM tokens WHERE token=?", (auth,))
        db.commit()
    return jsonify(ok=True)


# ----------------------------- API: Mail -----------------------------
@app.route("/api/send", methods=["POST"])
def api_send():
    u = require_user()
    recipient = (request.form.get("recipient") or "").strip().lower()
    subject = request.form.get("subject") or "(Không có tiêu đề)"
    body = request.form.get("body") or ""
    if not recipient or "@" not in recipient:
        return jsonify(error="Địa chỉ người nhận không hợp lệ."), 400
    db = get_db()
    cur = db.execute(
        "INSERT INTO mails(sender,recipient,subject,body,created) VALUES(?,?,?,?,?)",
        (u["email"], recipient, subject, body, time.time()),
    )
    mail_id = cur.lastrowid
    # Lưu các file đính kèm
    for f in request.files.getlist("files"):
        if not f or not f.filename:
            continue
        stored = secrets.token_hex(16)
        path = os.path.join(FILES_DIR, stored)
        f.save(path)
        size = os.path.getsize(path)
        if size > MAX_FILE:
            os.remove(path)
            return jsonify(error="File vượt quá 1GB."), 400
        mime = f.mimetype or mimetypes.guess_type(f.filename)[0] or "application/octet-stream"
        db.execute(
            "INSERT INTO attachments(mail_id,filename,stored,size,mime) VALUES(?,?,?,?,?)",
            (mail_id, f.filename, stored, size, mime),
        )
    db.commit()
    return jsonify(ok=True, id=mail_id)


def _mail_to_dict(db, row, box):
    atts = db.execute(
        "SELECT id,filename,size,mime FROM attachments WHERE mail_id=?", (row["id"],)
    ).fetchall()
    return {
        "id": row["id"],
        "sender": row["sender"],
        "recipient": row["recipient"],
        "subject": row["subject"],
        "body": row["body"],
        "created": row["created"],
        "read": bool(row["read_flag"]),
        "box": box,
        "attachments": [
            {"id": a["id"], "filename": a["filename"], "size": a["size"], "mime": a["mime"]}
            for a in atts
        ],
    }


@app.route("/api/inbox", methods=["GET"])
def api_inbox():
    u = require_user()
    db = get_db()
    rows = db.execute(
        "SELECT * FROM mails WHERE recipient=? AND deleted_by_recipient=0 ORDER BY created DESC",
        (u["email"],),
    ).fetchall()
    return jsonify(mails=[_mail_to_dict(db, r, "inbox") for r in rows])


@app.route("/api/sent", methods=["GET"])
def api_sent():
    u = require_user()
    db = get_db()
    rows = db.execute(
        "SELECT * FROM mails WHERE sender=? AND deleted_by_sender=0 ORDER BY created DESC",
        (u["email"],),
    ).fetchall()
    return jsonify(mails=[_mail_to_dict(db, r, "sent") for r in rows])


@app.route("/api/mail/<int:mid>/read", methods=["POST"])
def api_mark_read(mid):
    u = require_user()
    db = get_db()
    db.execute("UPDATE mails SET read_flag=1 WHERE id=? AND recipient=?",
               (mid, u["email"]))
    db.commit()
    return jsonify(ok=True)


@app.route("/api/mail/<int:mid>", methods=["DELETE"])
def api_delete(mid):
    u = require_user()
    db = get_db()
    row = db.execute("SELECT * FROM mails WHERE id=?", (mid,)).fetchone()
    if not row:
        return jsonify(error="Không tìm thấy thư."), 404
    if row["recipient"] == u["email"]:
        db.execute("UPDATE mails SET deleted_by_recipient=1 WHERE id=?", (mid,))
    if row["sender"] == u["email"]:
        db.execute("UPDATE mails SET deleted_by_sender=1 WHERE id=?", (mid,))
    db.commit()
    return jsonify(ok=True)


@app.route("/api/attachment/<int:aid>", methods=["GET"])
def api_attachment(aid):
    u = require_user()
    db = get_db()
    a = db.execute(
        "SELECT a.*, m.sender, m.recipient FROM attachments a "
        "JOIN mails m ON m.id=a.mail_id WHERE a.id=?", (aid,)
    ).fetchone()
    if not a:
        abort(404)
    if u["email"] not in (a["sender"], a["recipient"]):
        abort(403)
    path = os.path.join(FILES_DIR, a["stored"])
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=a["filename"],
                     mimetype=a["mime"])


# ----------------------------- Frontend -----------------------------
@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.errorhandler(413)
def too_large(e):
    return jsonify(error="Tệp quá lớn (giới hạn 1GB)."), 413


@app.errorhandler(401)
def unauthorized(e):
    return jsonify(error="Bạn cần đăng nhập."), 401


# Khởi tạo DB khi được nạp bởi gunicorn/host (không chạy __main__)
@app.before_request
def _ensure_db():
    global _DB_READY
    if not _DB_READY:
        init_db()
        _DB_READY = True


if __name__ == "__main__":
    init_db()
    _DB_READY = True
    print("VNThư server đang chạy tại http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
