
import os
import io
import uuid
from functools import wraps

import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, jsonify
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageOps, UnidentifiedImageError
from supabase import create_client

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FOOTRATE_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("Missing FOOTRATE_SECRET_KEY.")

DATABASE_URL = os.getenv("DATABASE_URL")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "").strip()
BUCKET_NAME = "FootPhotos"

if not DATABASE_URL:
    raise RuntimeError("Missing DATABASE_URL.")
if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Missing Supabase configuration.")

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.getenv("FLASK_ENV") == "production"
)

csrf = CSRFProtect(app)
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


def connect_db():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=10
    )


def init_db():
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS photo_reactions (
                    photo_id INTEGER NOT NULL REFERENCES photos(id)
                        ON DELETE CASCADE,
                    user_id INTEGER NOT NULL REFERENCES users(id)
                        ON DELETE CASCADE,
                    reaction_type VARCHAR(20) NOT NULL
                        CHECK (reaction_type IN ('like', 'superheart')),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (photo_id, user_id, reaction_type)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS comments (
                    id SERIAL PRIMARY KEY,
                    photo_id INTEGER NOT NULL REFERENCES photos(id)
                        ON DELETE CASCADE,
                    user_id INTEGER NOT NULL REFERENCES users(id)
                        ON DELETE CASCADE,
                    body TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_comments_photo
                ON comments(photo_id, created_at)
            """)


def is_admin():
    return bool(
        ADMIN_USERNAME
        and session.get("username")
        and session["username"].casefold() == ADMIN_USERNAME.casefold()
    )


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(ok=False, error="Please log in."), 401
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def public_image_url(filename):
    result = supabase.storage.from_(BUCKET_NAME).get_public_url(filename)
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        return result.get("publicUrl") or result.get("publicURL") or ""
    return str(result)


def storage_upload(filename, data):
    supabase.storage.from_(BUCKET_NAME).upload(
        path=filename,
        file=data,
        file_options={
            "content-type": "image/jpeg",
            "upsert": "false"
        }
    )


def storage_delete(filename):
    supabase.storage.from_(BUCKET_NAME).remove([filename])


def get_photo(photo_id):
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT p.id, p.user_id, p.filename, p.created_at,
                       u.username
                FROM photos p
                JOIN users u ON u.id = p.user_id
                WHERE p.id = %s
            """, (photo_id,))
            return cur.fetchone()


def wants_json():
    return (
        request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "application/json" in request.headers.get("Accept", "")
    )


@app.route("/")
def index():
    user_id = session.get("user_id")

    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT p.id, p.user_id, p.filename, p.created_at,
                       u.username,
                       (SELECT COUNT(*) FROM photo_reactions r
                        WHERE r.photo_id = p.id
                          AND r.reaction_type = 'like') AS like_count,
                       (SELECT COUNT(*) FROM photo_reactions r
                        WHERE r.photo_id = p.id
                          AND r.reaction_type = 'superheart') AS superheart_count,
                       EXISTS (
                           SELECT 1 FROM photo_reactions r
                           WHERE r.photo_id = p.id AND r.user_id = %s
                             AND r.reaction_type = 'like'
                       ) AS my_like,
                       EXISTS (
                           SELECT 1 FROM photo_reactions r
                           WHERE r.photo_id = p.id AND r.user_id = %s
                             AND r.reaction_type = 'superheart'
                       ) AS my_superheart
                FROM photos p
                JOIN users u ON u.id = p.user_id
                ORDER BY p.created_at DESC, p.id DESC
            """, (user_id or -1, user_id or -1))
            photos = cur.fetchall()

    for photo in photos:
        photo["image_url"] = public_image_url(photo["filename"])

    return render_template(
        "index.html",
        photos=photos,
        username=session.get("username"),
        user_id=user_id,
        admin=is_admin()
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 30:
            flash("Your username must be between 3 and 30 characters.")
            return render_template("register.html")

        if len(password) < 8:
            flash("Your password must be at least 8 characters long.")
            return render_template("register.html")

        with connect_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM users WHERE username = %s",
                    (username,)
                )
                if cur.fetchone():
                    flash("This username is already taken.")
                    return render_template("register.html")

                cur.execute("""
                    INSERT INTO users (username, password_hash)
                    VALUES (%s, %s)
                """, (username, generate_password_hash(password)))

        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with connect_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, password_hash
                    FROM users WHERE username = %s
                """, (username,))
                user = cur.fetchone()

        if not user or not check_password_hash(
            user["password_hash"], password
        ):
            flash("Incorrect username or password.")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded = request.files.get("photo")
    if not uploaded or not uploaded.filename:
        flash("Please select an image.")
        return redirect(url_for("index"))

    try:
        raw = uploaded.read()
        if not raw:
            raise ValueError("The file is empty.")

        with Image.open(io.BytesIO(raw)) as original:
            if original.format not in ("JPEG", "PNG", "WEBP"):
                raise ValueError("Only JPG, PNG, and WEBP images are allowed.")

            image = ImageOps.exif_transpose(original)
            image.load()

            if image.height <= image.width:
                raise ValueError("Only portrait images are allowed.")

            image = image.convert("RGB")
            output = io.BytesIO()
            image.save(output, format="JPEG", quality=92, optimize=True)
            image_bytes = output.getvalue()

    except (UnidentifiedImageError, OSError, ValueError) as exc:
        flash(str(exc) or "Invalid image file.")
        return redirect(url_for("index"))

    filename = f"{uuid.uuid4().hex}.jpg"

    try:
        storage_upload(filename, image_bytes)
        with connect_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO photos (user_id, filename)
                    VALUES (%s, %s)
                """, (session["user_id"], filename))
    except Exception:
        app.logger.exception("Image upload failed")
        try:
            storage_delete(filename)
        except Exception:
            app.logger.exception("Storage cleanup failed")
        flash("Image upload failed. Please try again.")
        return redirect(url_for("index"))

    flash("Image uploaded successfully.")
    return redirect(url_for("index"))


@app.route("/react/<int:photo_id>/<reaction_type>", methods=["POST"])
@login_required
def react(photo_id, reaction_type):
    if reaction_type not in ("like", "superheart"):
        return jsonify(ok=False, error="Unknown reaction."), 400

    if not get_photo(photo_id):
        return jsonify(ok=False, error="Image not found."), 404

    user_id = session["user_id"]

    try:
        with connect_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 1 FROM photo_reactions
                    WHERE photo_id=%s AND user_id=%s AND reaction_type=%s
                """, (photo_id, user_id, reaction_type))
                existed = cur.fetchone() is not None

                if existed:
                    cur.execute("""
                        DELETE FROM photo_reactions
                        WHERE photo_id=%s AND user_id=%s AND reaction_type=%s
                    """, (photo_id, user_id, reaction_type))
                    active = False
                else:
                    cur.execute("""
                        INSERT INTO photo_reactions
                            (photo_id, user_id, reaction_type)
                        VALUES (%s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (photo_id, user_id, reaction_type))
                    active = True

                cur.execute("""
                    SELECT COUNT(*) AS total FROM photo_reactions
                    WHERE photo_id=%s AND reaction_type=%s
                """, (photo_id, reaction_type))
                count = cur.fetchone()["total"]

        return jsonify(
            ok=True, active=active, count=count,
            photo_id=photo_id, reaction_type=reaction_type
        )
    except Exception:
        app.logger.exception("Reaction failed")
        return jsonify(ok=False, error="Could not save your reaction."), 500


@app.route("/comments/<int:photo_id>")
@login_required
def get_comments(photo_id):
    if not get_photo(photo_id):
        return jsonify(ok=False, error="Image not found."), 404

    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT c.id, c.body, c.created_at, u.username
                FROM comments c JOIN users u ON u.id = c.user_id
                WHERE c.photo_id=%s ORDER BY c.created_at, c.id
            """, (photo_id,))
            rows = cur.fetchall()

    return jsonify(comments=[{
        "id": row["id"],
        "username": row["username"],
        "body": row["body"],
        "created_at": row["created_at"].isoformat()
    } for row in rows])


@app.route("/comment/<int:photo_id>", methods=["POST"])
@login_required
def add_comment(photo_id):
    if not get_photo(photo_id):
        return jsonify(ok=False, error="Image not found."), 404

    data = request.get_json(silent=True) or {}
    body = data.get("body", "").strip()

    if not body or len(body) > 500:
        return jsonify(
            ok=False, error="Comments must be between 1 and 500 characters."
        ), 400

    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO comments (photo_id, user_id, body)
                VALUES (%s, %s, %s)
                RETURNING id, body, created_at
            """, (photo_id, session["user_id"], body))
            row = cur.fetchone()

    return jsonify(ok=True, comment={
        "id": row["id"],
        "username": session["username"],
        "body": row["body"],
        "created_at": row["created_at"].isoformat()
    })


@app.route("/delete/<int:photo_id>", methods=["POST"])
@login_required
def delete_photo(photo_id):
    photo = get_photo(photo_id)

    if not photo:
        return jsonify(ok=False, error="Image not found."), 404

    if photo["user_id"] != session["user_id"] and not is_admin():
        return jsonify(
            ok=False, error="You can only delete your own images."
        ), 403

    try:
        with connect_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM photos WHERE id=%s", (photo_id,))

        try:
            storage_delete(photo["filename"])
        except Exception:
            app.logger.exception("Could not delete image from storage")

        if wants_json():
            return jsonify(ok=True)
        return redirect(url_for("index"))

    except Exception:
        app.logger.exception("Image deletion failed")
        if wants_json():
            return jsonify(ok=False, error="Image deletion failed."), 500
        flash("Could not delete the image.")
        return redirect(url_for("index"))


@app.errorhandler(413)
def file_too_large(_error):
    message = "Images must be 5 MB or smaller."
    if wants_json():
        return jsonify(ok=False, error=message), 413
    flash(message)
    return redirect(url_for("index"))


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
