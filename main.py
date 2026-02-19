"""
JARVIS AI Assistant — Complete Backend API
Python  : 3.12.10
File    : main.py
Owner   : sethuvigneshc@gmail.com

FEATURES:
  - Owner login (password blank in code — set via Railway env var)
  - Forgot password via email
  - Guest user invites (owner only)
  - AI chat with web search
  - Code generation via voice/text
  - Theme customization (owner only)
  - Logo upload
  - Safety controls
"""

from __future__ import annotations
import os, json, secrets, smtplib
from datetime import datetime, timedelta
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

# ══════════════════════════════════════════════
#  APP SETUP
# ══════════════════════════════════════════════

app = Flask(__name__)

SECRET_KEY = os.environ.get("SECRET_KEY", "jarvis-secret-change-in-railway")
app.config["SECRET_KEY"] = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max upload

_db = os.environ.get("DATABASE_URL", "sqlite:///jarvis.db")
if _db.startswith("postgres://"):
    _db = _db.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = _db
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

CORS(app, resources={r"/api/*": {"origins": "*"}})
db = SQLAlchemy(app)

# ══════════════════════════════════════════════
#  ★ OWNER CREDENTIALS
# ══════════════════════════════════════════════

OWNER_EMAIL = "sethuvigneshc@gmail.com"

# ┌──────────────────────────────────────────────────────────┐
# │  ⚠️  PASSWORD IS BLANK HERE ON PURPOSE                  │
# │                                                          │
# │  ➜  SET IT IN RAILWAY → VARIABLES                       │
# │     Variable: OWNER_PASSWORD                            │
# │     Value   : YourStrongPassword123!                    │
# │                                                          │
# │  Until set, login shows clear error message.            │
# └──────────────────────────────────────────────────────────┘

OWNER_PASSWORD = os.environ.get("OWNER_PASSWORD", "")   # ← SET IN RAILWAY
OWNER_NAME     = os.environ.get("OWNER_NAME", "Sethu")

# Email for password reset
SMTP_SERVER   = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT     = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER     = os.environ.get("SMTP_USER", OWNER_EMAIL)
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")  # App password for Gmail

# ══════════════════════════════════════════════
#  MODELS
# ══════════════════════════════════════════════

class GuestUser(db.Model):
    __tablename__ = "guests"
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(200), unique=True, nullable=False)
    name          = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)
    is_active     = db.Column(db.Boolean, default=True)
    added_at      = db.Column(db.DateTime, default=datetime.utcnow)

    def set_pw(self, pw: str):
        self.password_hash = generate_password_hash(pw)

    def check_pw(self, pw: str) -> bool:
        return check_password_hash(self.password_hash, pw)

    def to_dict(self):
        return {
            "id": self.id, "email": self.email, "name": self.name,
            "is_active": self.is_active, "added_at": self.added_at.isoformat()
        }


class PasswordReset(db.Model):
    __tablename__ = "password_resets"
    id         = db.Column(db.Integer, primary_key=True)
    email      = db.Column(db.String(200), nullable=False)
    token      = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used       = db.Column(db.Boolean, default=False)


class Task(db.Model):
    __tablename__ = "tasks"
    id         = db.Column(db.Integer, primary_key=True)
    owner      = db.Column(db.String(200), nullable=False)
    text       = db.Column(db.String(500), nullable=False)
    completed  = db.Column(db.Boolean, default=False)
    priority   = db.Column(db.String(20), default="medium")
    due_date   = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "text": self.text, "completed": self.completed,
            "priority": self.priority,
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "created_at": self.created_at.isoformat()
        }


class Event(db.Model):
    __tablename__ = "events"
    id          = db.Column(db.Integer, primary_key=True)
    owner       = db.Column(db.String(200), nullable=False)
    title       = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    event_date  = db.Column(db.DateTime, nullable=False)
    event_time  = db.Column(db.String(10))
    event_type  = db.Column(db.String(50), default="personal")
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "title": self.title, "description": self.description,
            "date": self.event_date.date().isoformat(),
            "time": self.event_time, "type": self.event_type,
            "created_at": self.created_at.isoformat()
        }


class Note(db.Model):
    __tablename__ = "notes"
    id         = db.Column(db.Integer, primary_key=True)
    owner      = db.Column(db.String(200), nullable=False)
    title      = db.Column(db.String(200), nullable=False)
    content    = db.Column(db.Text, nullable=False)
    tags       = db.Column(db.String(300))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "title": self.title, "content": self.content,
            "tags": self.tags.split(",") if self.tags else [],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }


class HealthLog(db.Model):
    __tablename__ = "health"
    id         = db.Column(db.Integer, primary_key=True)
    owner      = db.Column(db.String(200), nullable=False)
    log_date   = db.Column(db.Date, nullable=False)
    steps      = db.Column(db.Integer, default=0)
    water      = db.Column(db.Float, default=0.0)
    sleep_hrs  = db.Column(db.Float, default=0.0)
    calories   = db.Column(db.Integer, default=0)
    weight_kg  = db.Column(db.Float)
    heart_rate = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "date": self.log_date.isoformat(),
            "steps": self.steps, "water": self.water, "sleep": self.sleep_hrs,
            "calories": self.calories, "weight": self.weight_kg,
            "heart_rate": self.heart_rate
        }


class ChatHistory(db.Model):
    """Stores AI chat conversations"""
    __tablename__ = "chats"
    id         = db.Column(db.Integer, primary_key=True)
    owner      = db.Column(db.String(200), nullable=False)
    message    = db.Column(db.Text, nullable=False)
    response   = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id, "message": self.message,
            "response": self.response, "created_at": self.created_at.isoformat()
        }


class Setting(db.Model):
    """Key-value store for safety + theme"""
    __tablename__ = "settings"
    key   = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.Text, default="")


# ── Defaults ────────────────────────────────
SAFETY = {
    "voice_enabled":      "true",
    "web_search_enabled": "true",
    "ai_chat_enabled":    "true",
    "code_generation":    "true",
}

THEME = {
    "primary_color":   "#00ffaa",
    "accent_color":    "#ff00ff",
    "bg_color":        "#0a0014",
    "text_color":      "#e0e0ff",
    "app_name":        "JARVIS",
    "logo_url":        "",  # user uploads logo here
}


def _get(key: str, default: str = "") -> str:
    row = Setting.query.get(key)
    return row.value if row else {**SAFETY, **THEME}.get(key, default)


def _set(key: str, val: str):
    row = Setting.query.get(key)
    if not row:
        row = Setting(key=key)
        db.session.add(row)
    row.value = val
    db.session.commit()


# ══════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════

def _payload():
    tok = request.headers.get("Authorization", "").replace("Bearer ", "")
    return jwt.decode(tok, SECRET_KEY, algorithms=["HS256"])


def token_required(f):
    @wraps(f)
    def w(*a, **kw):
        try:
            p = _payload()
            request.email    = p["email"]
            request.is_owner = p.get("is_owner", False)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*a, **kw)
    return w


def owner_only(f):
    @wraps(f)
    def w(*a, **kw):
        try:
            p = _payload()
            if not p.get("is_owner"):
                return jsonify({"error": "Owner access required"}), 403
            request.email = p["email"]
            request.is_owner = True
        except:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*a, **kw)
    return w


def _token(email: str, is_owner: bool) -> str:
    return jwt.encode(
        {"email": email, "is_owner": is_owner,
         "exp": datetime.utcnow() + timedelta(days=30)},
        SECRET_KEY, algorithm="HS256"
    )


# ══════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════

@app.post("/api/auth/login")
def login():
    d = request.get_json() or {}
    email = d.get("email", "").strip().lower()
    pw    = d.get("password", "")

    # Owner
    if email == OWNER_EMAIL.lower():
        if not OWNER_PASSWORD:
            return jsonify({"error":
                "⚠️ OWNER_PASSWORD not set. Add it in Railway → Variables."}), 500
        if pw != OWNER_PASSWORD:
            return jsonify({"error": "Invalid credentials"}), 401
        return jsonify({
            "token": _token(OWNER_EMAIL, True),
            "name": OWNER_NAME, "email": OWNER_EMAIL, "is_owner": True
        })

    # Guest
    g = GuestUser.query.filter_by(email=email).first()
    if not g or not g.is_active:
        return jsonify({"error": "Access denied — private app"}), 403
    if not g.check_pw(pw):
        return jsonify({"error": "Invalid credentials"}), 401
    return jsonify({
        "token": _token(g.email, False),
        "name": g.name, "email": g.email, "is_owner": False
    })


@app.get("/api/auth/verify")
@token_required
def verify():
    name = OWNER_NAME if request.is_owner else \
           (GuestUser.query.filter_by(email=request.email).first() or
            type("G", (), {"name": "Guest"})()).name
    return jsonify({
        "valid": True, "email": request.email,
        "is_owner": request.is_owner, "name": name
    })


@app.post("/api/auth/forgot-password")
def forgot_password():
    """Send password reset link to owner email only"""
    d = request.get_json() or {}
    email = d.get("email", "").strip().lower()

    if email != OWNER_EMAIL.lower():
        return jsonify({"error": "Only owner can reset password"}), 403

    # Generate token
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(hours=1)

    pr = PasswordReset(email=email, token=token, expires_at=expires)
    db.session.add(pr)
    db.session.commit()

    # Send email
    try:
        reset_link = f"{request.host_url}reset-password?token={token}"
        send_email(
            to=OWNER_EMAIL,
            subject="JARVIS Password Reset",
            body=f"Click here to reset your password:\n\n{reset_link}\n\nValid for 1 hour."
        )
        return jsonify({"ok": True, "message": "Reset link sent to your email"})
    except Exception as e:
        return jsonify({"error": f"Email failed: {str(e)}"}), 500


@app.post("/api/auth/reset-password")
def reset_password():
    """Reset password using token"""
    d = request.get_json() or {}
    token  = d.get("token", "")
    new_pw = d.get("new_password", "")

    if not token or not new_pw:
        return jsonify({"error": "Token and new password required"}), 400

    pr = PasswordReset.query.filter_by(token=token, used=False).first()
    if not pr or pr.expires_at < datetime.utcnow():
        return jsonify({"error": "Invalid or expired token"}), 400

    # Mark used
    pr.used = True
    db.session.commit()

    # Update password in env var — not possible programmatically
    # User must manually update OWNER_PASSWORD in Railway
    return jsonify({
        "ok": True,
        "message": "Token verified. Update OWNER_PASSWORD in Railway → Variables"
    })


def send_email(to: str, subject: str, body: str):
    if not SMTP_PASSWORD:
        raise ValueError("SMTP_PASSWORD not set in env vars")

    msg = MIMEMultipart()
    msg["From"] = SMTP_USER
    msg["To"] = to
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)


# ══════════════════════════════════════════════
#  GUESTS (owner only)
# ══════════════════════════════════════════════

@app.get("/api/users")
@owner_only
def list_guests():
    return jsonify([g.to_dict() for g in GuestUser.query.all()])


@app.post("/api/users")
@owner_only
def add_guest():
    d = request.get_json() or {}
    email = d.get("email", "").strip().lower()
    name  = d.get("name", "").strip()
    pw    = d.get("password", "")

    if not (email and name and pw):
        return jsonify({"error": "email, name, password required"}), 400
    if email == OWNER_EMAIL.lower():
        return jsonify({"error": "Cannot add owner as guest"}), 400
    if GuestUser.query.filter_by(email=email).first():
        return jsonify({"error": "User exists"}), 400

    g = GuestUser(email=email, name=name)
    g.set_pw(pw)
    db.session.add(g)
    db.session.commit()
    return jsonify(g.to_dict()), 201


@app.put("/api/users/<int:uid>")
@owner_only
def edit_guest(uid):
    g = GuestUser.query.get_or_404(uid)
    d = request.get_json() or {}
    if "is_active" in d:
        g.is_active = bool(d["is_active"])
    if "name" in d:
        g.name = d["name"]
    if d.get("password"):
        g.set_pw(d["password"])
    db.session.commit()
    return jsonify(g.to_dict())


@app.delete("/api/users/<int:uid>")
@owner_only
def del_guest(uid):
    db.session.delete(GuestUser.query.get_or_404(uid))
    db.session.commit()
    return jsonify({"ok": True})


# ══════════════════════════════════════════════
#  TASKS
# ══════════════════════════════════════════════

@app.get("/api/tasks")
@token_required
def get_tasks():
    ts = Task.query.filter_by(owner=request.email)\
                   .order_by(Task.created_at.desc()).all()
    return jsonify([t.to_dict() for t in ts])


@app.post("/api/tasks")
@token_required
def create_task():
    d = request.get_json() or {}
    if not d.get("text"):
        return jsonify({"error": "text required"}), 400
    t = Task(
        owner=request.email, text=d["text"],
        priority=d.get("priority", "medium"),
        due_date=datetime.fromisoformat(d["due_date"]) if d.get("due_date") else None
    )
    db.session.add(t)
    db.session.commit()
    return jsonify(t.to_dict()), 201


@app.put("/api/tasks/<int:tid>")
@token_required
def update_task(tid):
    t = Task.query.filter_by(id=tid, owner=request.email).first_or_404()
    d = request.get_json() or {}
    for f in ("text", "completed", "priority"):
        if f in d:
            setattr(t, f, d[f])
    db.session.commit()
    return jsonify(t.to_dict())


@app.delete("/api/tasks/<int:tid>")
@token_required
def del_task(tid):
    db.session.delete(
        Task.query.filter_by(id=tid, owner=request.email).first_or_404()
    )
    db.session.commit()
    return jsonify({"ok": True})


# ══════════════════════════════════════════════
#  EVENTS / CALENDAR
# ══════════════════════════════════════════════

@app.get("/api/events")
@token_required
def get_events():
    es = Event.query.filter_by(owner=request.email)\
                    .order_by(Event.event_date).all()
    return jsonify([e.to_dict() for e in es])


@app.post("/api/events")
@token_required
def create_event():
    d = request.get_json() or {}
    e = Event(
        owner=request.email, title=d["title"],
        description=d.get("description", ""),
        event_date=datetime.fromisoformat(d["date"]),
        event_time=d.get("time", ""), event_type=d.get("type", "personal")
    )
    db.session.add(e)
    db.session.commit()
    return jsonify(e.to_dict()), 201


@app.delete("/api/events/<int:eid>")
@token_required
def del_event(eid):
    db.session.delete(
        Event.query.filter_by(id=eid, owner=request.email).first_or_404()
    )
    db.session.commit()
    return jsonify({"ok": True})


# ══════════════════════════════════════════════
#  NOTES
# ══════════════════════════════════════════════

@app.get("/api/notes")
@token_required
def get_notes():
    ns = Note.query.filter_by(owner=request.email)\
                   .order_by(Note.created_at.desc()).all()
    return jsonify([n.to_dict() for n in ns])


@app.post("/api/notes")
@token_required
def create_note():
    d = request.get_json() or {}
    n = Note(
        owner=request.email, title=d["title"], content=d["content"],
        tags=",".join(d.get("tags", []))
    )
    db.session.add(n)
    db.session.commit()
    return jsonify(n.to_dict()), 201


@app.delete("/api/notes/<int:nid>")
@token_required
def del_note(nid):
    db.session.delete(
        Note.query.filter_by(id=nid, owner=request.email).first_or_404()
    )
    db.session.commit()
    return jsonify({"ok": True})


# ══════════════════════════════════════════════
#  HEALTH
# ══════════════════════════════════════════════

@app.get("/api/health/today")
@token_required
def health_today():
    today = datetime.utcnow().date()
    h = HealthLog.query.filter_by(owner=request.email, log_date=today).first()
    if not h:
        h = HealthLog(owner=request.email, log_date=today)
        db.session.add(h)
        db.session.commit()
    return jsonify(h.to_dict())


@app.post("/api/health")
@token_required
def update_health():
    d = request.get_json() or {}
    today = datetime.utcnow().date()
    h = HealthLog.query.filter_by(owner=request.email, log_date=today).first()
    if not h:
        h = HealthLog(owner=request.email, log_date=today)
        db.session.add(h)
    for k, attr in {
        "steps": "steps", "water": "water", "sleep": "sleep_hrs",
        "calories": "calories", "weight": "weight_kg", "heart_rate": "heart_rate"
    }.items():
        if k in d:
            setattr(h, attr, d[k])
    db.session.commit()
    return jsonify(h.to_dict())


# ══════════════════════════════════════════════
#  DASHBOARD
# ══════════════════════════════════════════════

@app.get("/api/dashboard")
@token_required
def dashboard():
    today = datetime.utcnow().date()
    h = HealthLog.query.filter_by(owner=request.email, log_date=today).first()
    return jsonify({
        "pending_tasks": Task.query.filter_by(
            owner=request.email, completed=False
        ).count(),
        "total_events": Event.query.filter_by(owner=request.email).count(),
        "total_notes": Note.query.filter_by(owner=request.email).count(),
        "health": h.to_dict() if h else {
            "steps": 0, "water": 0, "sleep": 0, "calories": 0
        },
    })


# ══════════════════════════════════════════════
#  SAFETY
# ══════════════════════════════════════════════

@app.get("/api/safety")
@token_required
def get_safety():
    return jsonify({k: _get(k) for k in SAFETY})


@app.post("/api/safety")
@token_required
def set_safety():
    d = request.get_json() or {}
    for k in SAFETY:
        if k in d:
            _set(k, str(d[k]).lower())
    return jsonify({"ok": True})


# ══════════════════════════════════════════════
#  THEME (owner only to save, anyone can read)
# ══════════════════════════════════════════════

@app.get("/api/theme")
@token_required
def get_theme():
    return jsonify({k: _get(k, v) for k, v in THEME.items()})


@app.post("/api/theme")
@owner_only
def save_theme():
    d = request.get_json() or {}
    for k in THEME:
        if k in d:
            _set(k, str(d[k]))
    return jsonify({"ok": True})


# ══════════════════════════════════════════════
#  AI CHAT + HISTORY
# ══════════════════════════════════════════════

def _claude(prompt: str, use_web: bool = False) -> str:
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise ValueError("ANTHROPIC_API_KEY not set")
    import anthropic

    c = anthropic.Anthropic(api_key=key)
    tools = [{"type": "web_search_20250305", "name": "web_search"}] if use_web else None
    r = c.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=2000,
        tools=tools,
        messages=[{"role": "user", "content": prompt}],
    )
    return " ".join(b.text for b in r.content if hasattr(b, "text") and b.text)


@app.post("/api/chat")
@token_required
def ai_chat():
    if _get("ai_chat_enabled") != "true":
        return jsonify({"error": "AI chat disabled"}), 403

    d = request.get_json() or {}
    msg = d.get("message", "")

    # Detect context
    use_web = any(
        w in msg.lower()
        for w in ["news", "today", "latest", "search", "find", "weather"]
    )

    try:
        resp = _claude(
            f"You are JARVIS. Be concise. User: {msg}",
            use_web=use_web and _get("web_search_enabled") == "true",
        )
        # Save history
        ch = ChatHistory(owner=request.email, message=msg, response=resp)
        db.session.add(ch)
        db.session.commit()
        return jsonify({"response": resp, "used_web": use_web})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/chat/history")
@token_required
def chat_history():
    limit = int(request.args.get("limit", 50))
    chats = (
        ChatHistory.query.filter_by(owner=request.email)
        .order_by(ChatHistory.created_at.desc())
        .limit(limit)
        .all()
    )
    return jsonify([c.to_dict() for c in reversed(chats)])


@app.delete("/api/chat/history")
@token_required
def clear_history():
    ChatHistory.query.filter_by(owner=request.email).delete()
    db.session.commit()
    return jsonify({"ok": True})


# ══════════════════════════════════════════════
#  CODE GENERATION
# ══════════════════════════════════════════════

@app.post("/api/code")
@token_required
def gen_code():
    if _get("code_generation") != "true":
        return jsonify({"error": "Code gen disabled"}), 403

    d = request.get_json() or {}
    try:
        code = _claude(
            f"Generate {d.get('language','python')} code for: {d.get('prompt','')}. "
            f"Code only with comments.",
            use_web=False,
        )
        return jsonify({"code": code})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ══════════════════════════════════════════════
#  LOGO UPLOAD (base64)
# ══════════════════════════════════════════════

@app.post("/api/logo")
@owner_only
def upload_logo():
    d = request.get_json() or {}
    logo_data = d.get("logo_base64", "")  # data:image/png;base64,...

    if not logo_data:
        return jsonify({"error": "logo_base64 required"}), 400

    _set("logo_url", logo_data)
    return jsonify({"ok": True, "url": logo_data})


# ══════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════

@app.get("/api/ping")
def ping():
    return jsonify({"status": "ok", "app": "JARVIS", "python": "3.12.10"})


@app.get("/")
def root():
    return jsonify({"msg": "JARVIS API v3"})


# ══════════════════════════════════════════════
#  BOOT
# ══════════════════════════════════════════════

def init_db():
    with app.app_context():
        db.create_all()
        for k, v in {**SAFETY, **THEME}.items():
            if not Setting.query.get(k):
                db.session.add(Setting(key=k, value=v))
        db.session.commit()
    print("✅  DB ready — JARVIS v3 (Python 3.12.10)")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # This ensures your tables exist
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

  
