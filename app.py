
import os
import io
import logging
import secrets
from datetime import datetime, timezone
from functools import wraps

import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
from supabase import create_client
from PIL import Image, UnidentifiedImageError

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
    jsonify,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash


# --------------------------------------------------
# BEÁLLÍTÁSOK
# --------------------------------------------------

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("footrate")

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("FOOTRATE_SECRET_KEY")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.getenv("FLASK_ENV") == "production"
)

if not app.config["SECRET_KEY"]:
    raise RuntimeError(
        "Hiányzik a FOOTRATE_SECRET_KEY környezeti változó."
    )

csrf = CSRFProtect(app)

DATABASE_URL = os.getenv("DATABASE_URL")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
STORAGE_BUCKET = "FootPhotos"

if not DATABASE_URL:
    raise RuntimeError("Hiányzik a DATABASE_URL környezeti változó.")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError(
        "Hiányzik a SUPABASE_URL vagy SUPABASE_KEY környezeti változó."
    )

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# --------------------------------------------------
# ADATBÁZIS
# --------------------------------------------------

def connect_db():
    """Kapcsolódás a meglévő Supabase PostgreSQL-adatbázishoz."""
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=15,
    )


def init_db():
    """
    Csak a reakciók és kommentek tábláit biztosítja.
    A meglévő users, photos és ratings táblákat nem törli.
    """
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.photo_reactions (
                    id BIGSERIAL PRIMARY KEY,
                    photo_id BIGINT NOT NULL
                        REFERENCES public.photos(id) ON DELETE CASCADE,
                    user_id BIGINT NOT NULL
                        REFERENCES public.users(id) ON DELETE CASCADE,
                    reaction_type TEXT NOT NULL
                        CHECK (reaction_type IN ('like', 'superheart')),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)

            cur.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS
                    photo_reactions_unique_user_photo_type
                ON public.photo_reactions
                    (photo_id, user_id, reaction_type)
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS public.comments (
                    id BIGSERIAL PRIMARY KEY,
                    photo_id BIGINT NOT NULL
                        REFERENCES public.photos(id) ON DELETE CASCADE,
                    user_id BIGINT NOT NULL
                        REFERENCES public.users(id) ON DELETE CASCADE,
                    body TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)

            cur.execute("""
                CREATE INDEX IF NOT EXISTS comments_photo_created_idx
                ON public.comments (photo_id, created_at)
            """)


# --------------------------------------------------
# FELHASZNÁLÓK ÉS BEJELENTKEZÉS
# --------------------------------------------------

def current_user_id():
    return session.get("user_id")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user_id():
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({
                    "ok": False,
                    "error": "A művelethez be kell jelentkezned."
                }), 401

            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


def get_current_user():
    user_id = current_user_id()

    if not user_id:
        return None

    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username
                FROM public.users
                WHERE id = %s
            """, (user_id,))
            return cur.fetchone()


# --------------------------------------------------
# KÉPTÁROLÁS
# --------------------------------------------------

def public_image_url(filename):
    """A Supabase nyilvános képtárolójából lekéri a kép URL-jét."""
    result = supabase.storage.from_(STORAGE_BUCKET).get_public_url(
        filename
    )

    if isinstance(result, str):
        return result

    if isinstance(result, dict):
        return (
            result.get("publicUrl")
            or result.get("publicURL")
            or result.get("public_url")
        )

    return str(result)


def storage_upload(image_bytes, filename):
    """JPEG-kép feltöltése a meglévő FootPhotos bucketbe."""
    result = supabase.storage.from_(STORAGE_BUCKET).upload(
        path=filename,
        file=image_bytes,
        file_options={
            "content-type": "image/jpeg",
            "upsert": "false",
        },
    )
    return result


def storage_delete(filename):
    """Kép törlése a Supabase Storage-ból."""
    return supabase.storage.from_(STORAGE_BUCKET).remove([filename])


def get_photo(photo_id):
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, user_id, filename, created_at
                FROM public.photos
                WHERE id = %s
            """, (photo_id,))
            return cur.fetchone()


# --------------------------------------------------
# KEZDŐLAP
# --------------------------------------------------

@app.route("/")
@login_required
def index():
    user = get_current_user()

    if not user:
        session.clear()
        return redirect(url_for("login"))

    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    p.id,
                    p.user_id,
                    p.filename,
                    p.created_at,
                    u.username,

                    (
                        SELECT COUNT(*)
                        FROM public.photo_reactions r
                        WHERE r.photo_id = p.id
                          AND r.reaction_type = 'like'
                    ) AS like_count,

                    (
                        SELECT COUNT(*)
                        FROM public.photo_reactions r
                        WHERE r.photo_id = p.id
                          AND r.reaction_type = 'superheart'
                    ) AS superheart_count,

                    EXISTS (
                        SELECT 1
                        FROM public.photo_reactions r
                        WHERE r.photo_id = p.id
                          AND r.user_id = %s
                          AND r.reaction_type = 'like'
                    ) AS my_like,

                    EXISTS (
                        SELECT 1
                        FROM public.photo_reactions r
                        WHERE r.photo_id = p.id
                          AND r.user_id = %s
                          AND r.reaction_type = 'superheart'
                    ) AS my_superheart

                FROM public.photos p
                JOIN public.users u ON u.id = p.user_id
                ORDER BY p.created_at DESC NULLS LAST, p.id DESC
            """, (user["id"], user["id"]))

            rows = cur.fetchall()

    photos = []

    for photo in rows:
        item = dict(photo)
        item["image_url"] = public_image_url(item["filename"])
        photos.append(item)

    return render_template(
        "index.html",
        photos=photos,
        username=user["username"],
    )


# --------------------------------------------------
# REGISZTRÁCIÓ
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user_id():
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 30:
            flash("A felhasználónév 3–30 karakter hosszú legyen.")
            return render_template("register.html")

        if not username.replace("_", "").isalnum():
            flash("A felhasználónévben csak betű, szám és _ lehet.")
            return render_template("register.html")

        if len(password) < 8:
            flash("A jelszó legalább 8 karakter hosszú legyen.")
            return render_template("register.html")

        try:
            password_hash = generate_password_hash(password)

            with connect_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT id
                        FROM public.users
                        WHERE LOWER(username) = LOWER(%s)
                    """, (username,))

                    if cur.fetchone():
                        flash("Ez a felhasználónév már foglalt.")
                        return render_template("register.html")

                    cur.execute("""
                        INSERT INTO public.users
                            (username, password_hash)
                        VALUES (%s, %s)
                        RETURNING id
                    """, (username, password_hash))

                    user = cur.fetchone()

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = username

            return redirect(url_for("index"))

        except Exception:
            logger.exception("Regisztrációs hiba")
            flash("A regisztráció nem sikerült. Próbáld újra.")

    return render_template("register.html")


# --------------------------------------------------
# BEJELENTKEZÉS
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user_id():
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            with connect_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        SELECT id, username, password_hash
                        FROM public.users
                        WHERE LOWER(username) = LOWER(%s)
                    """, (username,))
                    user = cur.fetchone()

            if (
                not user
                or not check_password_hash(
                    user["password_hash"], password
                )
            ):
                flash("Hibás felhasználónév vagy jelszó.")
                return render_template("login.html")

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(url_for("index"))

        except Exception:
            logger.exception("Bejelentkezési hiba")
            flash("A bejelentkezés most nem sikerült.")

    return render_template("login.html")


# --------------------------------------------------
# KIJELENTKEZÉS
# --------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------
# KÉPFELTÖLTÉS
# --------------------------------------------------

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded_file = request.files.get("photo")

    if not uploaded_file or not uploaded_file.filename:
        flash("Válassz ki egy képet.")
        return redirect(url_for("index"))

    try:
        raw_bytes = uploaded_file.read()

        if not raw_bytes:
            flash("A kiválasztott fájl üres.")
            return redirect(url_for("index"))

        if len(raw_bytes) > 5 * 1024 * 1024:
            flash("A kép legfeljebb 5 MB lehet.")
            return redirect(url_for("index"))

        # A fájlt valódi képként próbáljuk megnyitni.
        image = Image.open(io.BytesIO(raw_bytes))
        image.verify()

        image = Image.open(io.BytesIO(raw_bytes))
        image = image.convert("RGB")

        # Méretkorlát a túl nagy képek feldolgozásához.
        image.thumbnail((2400, 2400))

        output = io.BytesIO()
        image.save(output, format="JPEG", quality=88, optimize=True)
        image_bytes = output.getvalue()

        filename = f"{secrets.token_hex(20)}.jpg"
        user_id = current_user_id()

        # Először feltöltjük a képet a Storage-ba.
        storage_upload(image_bytes, filename)

        try:
            with connect_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO public.photos
                            (user_id, filename, created_at)
                        VALUES (%s, %s, %s)
                    """, (
                        user_id,
                        filename,
                        datetime.now(timezone.utc),
                    ))
        except Exception:
            # Ha az adatbázis mentése nem sikerül,
            # megpróbáljuk eltávolítani az árván maradt fájlt.
            try:
                storage_delete(filename)
            except Exception:
                logger.exception("Árva Storage-fájl törlése sikertelen.")
            raise

        flash("A kép sikeresen feltöltve.")

    except (UnidentifiedImageError, OSError, ValueError):
        flash("A fájl nem érvényes kép. JPG, PNG vagy WEBP fájlt használj.")

    except Exception:
        logger.exception("Képfeltöltési hiba")
        flash("A képfeltöltés nem sikerült. Ellenőrizd a szerver naplóját.")

    return redirect(url_for("index"))


# --------------------------------------------------
# KEDVELÉS ÉS SZUPERHÍV – AJAX
# --------------------------------------------------

@app.route(
    "/react/<int:photo_id>/<reaction_type>",
    methods=["POST"]
)
@login_required
def react(photo_id, reaction_type):
    if reaction_type not in ("like", "superheart"):
        abort(404)

    if not get_photo(photo_id):
        abort(404)

    user_id = current_user_id()

    try:
        with connect_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id
                    FROM public.photo_reactions
                    WHERE photo_id = %s
                      AND user_id = %s
                      AND reaction_type = %s
                """, (photo_id, user_id, reaction_type))

                existing = cur.fetchone()

                if existing:
                    cur.execute("""
                        DELETE FROM public.photo_reactions
                        WHERE id = %s
                    """, (existing["id"],))
                    active = False
                else:
                    cur.execute("""
                        INSERT INTO public.photo_reactions
                            (photo_id, user_id, reaction_type)
                        VALUES (%s, %s, %s)
                        ON CONFLICT
                            (photo_id, user_id, reaction_type)
                        DO NOTHING
                    """, (photo_id, user_id, reaction_type))
                    active = True

                cur.execute("""
                    SELECT COUNT(*) AS total
                    FROM public.photo_reactions
                    WHERE photo_id = %s
                      AND reaction_type = %s
                """, (photo_id, reaction_type))

                count = cur.fetchone()["total"]

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({
                "ok": True,
                "active": active,
                "count": count,
                "photo_id": photo_id,
                "reaction_type": reaction_type,
            })

        return redirect(url_for("index"))

    except Exception:
        logger.exception("Reakciómentési hiba")

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({
                "ok": False,
                "error": "A reakció mentése nem sikerült.",
            }), 500

        flash("A reakció mentése nem sikerült.")
        return redirect(url_for("index"))


# --------------------------------------------------
# KOMMENTEK LEKÉRÉSE
# --------------------------------------------------

@app.route("/comments/<int:photo_id>", methods=["GET"])
@login_required
def comments(photo_id):
    if not get_photo(photo_id):
        return jsonify({
            "error": "A kép nem található."
        }), 404

    try:
        with connect_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT
                        c.id,
                        c.body,
                        c.created_at,
                        u.username
                    FROM public.comments c
                    JOIN public.users u ON u.id = c.user_id
                    WHERE c.photo_id = %s
                    ORDER BY c.created_at ASC, c.id ASC
                """, (photo_id,))

                rows = cur.fetchall()

        return jsonify({
            "comments": [
                {
                    "id": row["id"],
                    "username": row["username"],
                    "body": row["body"],
                    "created_at": (
                        row["created_at"].isoformat()
                        if row["created_at"]
                        else None
                    ),
                }
                for row in rows
            ]
        })

    except Exception:
        logger.exception("Kommentek lekérése sikertelen.")
        return jsonify({
            "error": "A kommentek betöltése nem sikerült."
        }), 500


# --------------------------------------------------
# KOMMENT ÍRÁSA – AJAX
# --------------------------------------------------

@app.route("/comment/<int:photo_id>", methods=["POST"])
@login_required
def comment(photo_id):
    if not get_photo(photo_id):
        return jsonify({
            "ok": False,
            "error": "A kép nem található.",
        }), 404

    data = request.get_json(silent=True) or {}
    body = str(data.get("body", "")).strip()

    if not body:
        return jsonify({
            "ok": False,
            "error": "A komment nem lehet üres.",
        }), 400

    if len(body) > 500:
        return jsonify({
            "ok": False,
            "error": "A komment legfeljebb 500 karakter lehet.",
        }), 400

    try:
        with connect_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO public.comments
                        (photo_id, user_id, body)
                    VALUES (%s, %s, %s)
                    RETURNING id, body, created_at
                """, (
                    photo_id,
                    current_user_id(),
                    body,
                ))

                saved = cur.fetchone()

                cur.execute("""
                    SELECT username
                    FROM public.users
                    WHERE id = %s
                """, (current_user_id(),))

                user = cur.fetchone()

        return jsonify({
            "ok": True,
            "comment": {
                "id": saved["id"],
                "body": saved["body"],
                "username": user["username"],
                "created_at": (
                    saved["created_at"].isoformat()
                    if saved["created_at"]
                    else None
                ),
            },
        }), 201

    except Exception:
        logger.exception("Komment mentése sikertelen.")
        return jsonify({
            "ok": False,
            "error": "A komment mentése nem sikerült.",
        }), 500


# --------------------------------------------------
# SAJÁT KÉP TÖRLÉSE
# --------------------------------------------------

@app.route("/delete/<int:photo_id>", methods=["POST"])
@login_required
def delete_photo(photo_id):
    user_id = current_user_id()
    is_ajax = (
        request.headers.get("X-Requested-With") == "XMLHttpRequest"
    )

    try:
        # A tulajdonjogot a szerver ellenőrzi.
        with connect_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, user_id, filename
                    FROM public.photos
                    WHERE id = %s
                """, (photo_id,))

                photo = cur.fetchone()

                if not photo:
                    if is_ajax:
                        return jsonify({
                            "ok": False,
                            "error": "A kép nem található.",
                        }), 404
                    abort(404)

                if photo["user_id"] != user_id:
                    if is_ajax:
                        return jsonify({
                            "ok": False,
                            "error": "Csak a saját képedet törölheted.",
                        }), 403
                    abort(403)

                cur.execute("""
                    DELETE FROM public.photos
                    WHERE id = %s AND user_id = %s
                """, (photo_id, user_id))

                if cur.rowcount != 1:
                    if is_ajax:
                        return jsonify({
                            "ok": False,
                            "error": "A képet nem sikerült törölni.",
                        }), 409
                    abort(409)

        # Az adatbázis törlése után megpróbáljuk törölni a fájlt is.
        try:
            storage_delete(photo["filename"])
        except Exception:
            logger.exception(
                "Az adatbázis-bejegyzés törlődött, de a Storage-fájl megmaradhat."
            )

        if is_ajax:
            return jsonify({
                "ok": True,
                "photo_id": photo_id,
            })

        flash("A saját képed törölve.")
        return redirect(url_for("index"))

    except Exception:
        logger.exception("Képtörlési hiba")

        if is_ajax:
            return jsonify({
                "ok": False,
                "error": "A kép törlése nem sikerült.",
            }), 500

        flash("A kép törlése nem sikerült.")
        return redirect(url_for("index"))


# --------------------------------------------------
# HIBAKEZELÉS
# --------------------------------------------------

@app.errorhandler(413)
def file_too_large(_error):
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({
            "ok": False,
            "error": "A fájl túl nagy. A maximális méret 5 MB.",
        }), 413

    flash("A fájl túl nagy. A maximális méret 5 MB.")
    return redirect(url_for("index"))


@app.errorhandler(400)
def bad_request(_error):
    if request.path.startswith(("/react/", "/comment/", "/delete/")):
        return jsonify({
            "ok": False,
            "error": "Érvénytelen kérés vagy lejárt CSRF-token.",
        }), 400

    return "Érvénytelen kérés.", 400


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


# --------------------------------------------------
# INDÍTÁS
# --------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
