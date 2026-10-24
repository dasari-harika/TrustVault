
import os
import sqlite3
import secrets
from pathlib import Path
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, request, jsonify, session,
    send_from_directory, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "private_uploads"
DATABASE = Path("/tmp/trustvault.db")

UPLOAD_DIR = Path("/tmp/private_uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
app = Flask(__name__)
@app.get("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")
app.config["SECRET_KEY"] = os.environ.get(
    "TRUSTVAULT_SECRET_KEY", secrets.token_hex(32)
)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("TRUSTVAULT_HTTPS") == "1"
)

ALLOWED_EXTENSIONS = {
    ".pdf", ".txt", ".png", ".jpg", ".jpeg",
    ".doc", ".docx", ".xls", ".xlsx", ".csv"
}


def connect_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    with connect_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS tenants (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                tenant_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK(role IN ('admin','editor','viewer')),
                UNIQUE(tenant_id, email),
                FOREIGN KEY(tenant_id) REFERENCES tenants(id)
            );

            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY,
                tenant_id INTEGER NOT NULL,
                owner_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                FOREIGN KEY(tenant_id) REFERENCES tenants(id),
                FOREIGN KEY(owner_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS document_shares (
                document_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                permission TEXT NOT NULL
                    CHECK(permission IN ('viewer','editor')),
                PRIMARY KEY(document_id, user_id),
                FOREIGN KEY(document_id) REFERENCES documents(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY,
                tenant_id INTEGER NOT NULL,
                user_id INTEGER,
                action TEXT NOT NULL,
                document_id INTEGER,
                created_at TEXT NOT NULL
            );
        """)

        # Demo accounts for local testing only.
        db.execute(
            "INSERT OR IGNORE INTO tenants(id, name) VALUES (1, ?)",
            ("Acme Demo",)
        )
        db.execute(
            """INSERT OR IGNORE INTO users
               (tenant_id, email, password_hash, role)
               VALUES (1, ?, ?, 'admin')""",
            ("admin@acme.test",
             generate_password_hash("ChangeMe123!"))
        )
        db.execute(
            """INSERT OR IGNORE INTO users
               (tenant_id, email, password_hash, role)
               VALUES (1, ?, ?, 'viewer')""",
            ("viewer@acme.test",
             generate_password_hash("ViewerDemo123!"))
        )


def audit(db, action, document_id=None):
    db.execute(
        """INSERT INTO audit_logs
           (tenant_id, user_id, action, document_id, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (
            g.user["tenant_id"], g.user["id"], action,
            document_id,
            datetime.now(timezone.utc).isoformat()
        )
    )


@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        with connect_db() as db:
            g.user = db.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return jsonify(error="Login required"), 401
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] not in roles:
                return jsonify(error="Permission denied"), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


def get_document(db, document_id):
    # Always scope document lookups to the logged-in tenant.
    return db.execute(
        """SELECT * FROM documents
           WHERE id = ? AND tenant_id = ?""",
        (document_id, g.user["tenant_id"])
    ).fetchone()


def can_access(db, document, edit=False):
    if document is None:
        return False

    if g.user["role"] == "admin":
        return True

    if document["owner_id"] == g.user["id"]:
        return True

    share = db.execute(
        """SELECT permission FROM document_shares
           WHERE document_id = ? AND user_id = ?""",
        (document["id"], g.user["id"])
    ).fetchone()

    if share is None:
        return False

    return not edit or share["permission"] == "editor"


@app.get("/api/health")
def health():
    return jsonify(status="ok", service="TrustVault API")


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password", "")

    with connect_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

        if not user or not check_password_hash(
            user["password_hash"], password
        ):
            return jsonify(error="Invalid email or password"), 401

        session.clear()
        session["user_id"] = user["id"]
        audit(db, "login")

        return jsonify(
            message="Login successful",
            user={
                "id": user["id"],
                "email": user["email"],
                "role": user["role"],
                "tenant_id": user["tenant_id"]
            }
        )


@app.post("/api/logout")
@login_required
def logout():
    with connect_db() as db:
        audit(db, "logout")
    session.clear()
    return jsonify(message="Logged out")


@app.get("/api/me")
@login_required
def me():
    return jsonify(
        id=g.user["id"],
        email=g.user["email"],
        role=g.user["role"],
        tenant_id=g.user["tenant_id"]
    )


@app.get("/api/documents")
@login_required
def list_documents():
    with connect_db() as db:
        rows = db.execute(
            """SELECT d.* FROM documents d
               WHERE d.tenant_id = ?
               AND (
                   d.owner_id = ?
                   OR ? = 'admin'
                   OR EXISTS (
                       SELECT 1 FROM document_shares s
                       WHERE s.document_id = d.id
                       AND s.user_id = ?
                   )
               )
               ORDER BY d.id DESC""",
            (
                g.user["tenant_id"], g.user["id"],
                g.user["role"], g.user["id"]
            )
        ).fetchall()

        return jsonify(documents=[
            {
                "id": row["id"],
                "filename": row["filename"],
                "uploaded_at": row["uploaded_at"],
                "owner_id": row["owner_id"]
            } for row in rows
        ])


@app.post("/api/documents")
@roles_required("admin", "editor")
def upload_document():
    file = request.files.get("file")

    if not file or not file.filename:
        return jsonify(error="Choose a file"), 400

    filename = secure_filename(file.filename)
    if not filename or Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        return jsonify(error="File type not allowed"), 400

    stored_name = secrets.token_hex(16) + Path(filename).suffix.lower()
    saved_path = UPLOAD_DIR / stored_name

    with connect_db() as db:
        try:
            file.save(saved_path)
            cursor = db.execute(
                """INSERT INTO documents
                   (tenant_id, owner_id, filename, stored_name, uploaded_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    g.user["tenant_id"], g.user["id"], filename,
                    stored_name,
                    datetime.now(timezone.utc).isoformat()
                )
            )
            document_id = cursor.lastrowid
            audit(db, "upload", document_id)
        except Exception:
            saved_path.unlink(missing_ok=True)
            raise

    return jsonify(
        message="Upload successful", document_id=document_id,
        filename=filename
    ), 201


@app.get("/api/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    with connect_db() as db:
        document = get_document(db, document_id)

        if not can_access(db, document):
            return jsonify(error="Document not found or access denied"), 404

        audit(db, "download", document_id)
        filename = document["filename"]
        stored_name = document["stored_name"]

    return send_from_directory(
        UPLOAD_DIR, stored_name,
        as_attachment=True, download_name=filename
    )


@app.post("/api/documents/<int:document_id>/share")
@roles_required("admin", "editor")
def share_document(document_id):
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    permission = data.get("permission", "viewer")

    if permission not in ("viewer", "editor"):
        return jsonify(error="Invalid permission"), 400

    with connect_db() as db:
        document = get_document(db, document_id)
        if document is None:
            return jsonify(error="Document not found"), 404

        if g.user["role"] != "admin" and document["owner_id"] != g.user["id"]:
            return jsonify(error="Only the owner or admin can share"), 403

        recipient = db.execute(
            """SELECT id FROM users
               WHERE tenant_id = ? AND email = ?""",
            (g.user["tenant_id"], email)
        ).fetchone()

        if recipient is None:
            return jsonify(error="User not found in this company"), 404

        db.execute(
            """INSERT INTO document_shares
               (document_id, user_id, permission)
               VALUES (?, ?, ?)
               ON CONFLICT(document_id, user_id)
               DO UPDATE SET permission = excluded.permission""",
            (document_id, recipient["id"], permission)
        )
        audit(db, "share", document_id)

    return jsonify(message="Document shared")


@app.get("/api/audit")
@roles_required("admin")
def get_audit():
    with connect_db() as db:
        rows = db.execute(
            """SELECT id, user_id, action, document_id, created_at
               FROM audit_logs WHERE tenant_id = ?
               ORDER BY id DESC LIMIT 200""",
            (g.user["tenant_id"],)
        ).fetchall()

    return jsonify(events=[dict(row) for row in rows])


@app.errorhandler(413)
def file_too_large(_error):
    return jsonify(error="File exceeds the 10 MB limit"), 413


@app.errorhandler(500)
def server_error(_error):
    return jsonify(error="Internal server error"), 500


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
