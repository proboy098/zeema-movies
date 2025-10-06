from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3, os, datetime, json

APP_SECRET = os.environ.get("APP_SECRET", "change-me-please")
UPLOAD_FOLDER = os.path.join("static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

app = Flask(__name__)
app.config["SECRET_KEY"] = APP_SECRET
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

DB_PATH = os.path.join(os.path.dirname(__file__), "site.db")

def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = get_db()
    cur = con.cursor()
    # users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL,
        last_login_at TEXT,
        last_ip TEXT
    );
    """)
    # movies
    cur.execute("""
    CREATE TABLE IF NOT EXISTS movies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        year INTEGER,
        genre TEXT,
        video_url TEXT,
        poster_filename TEXT,
        created_by_user_id INTEGER,
        created_at TEXT NOT NULL,
        FOREIGN KEY(created_by_user_id) REFERENCES users(id)
    );
    """)
    # audit log
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        meta TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    """)
    con.commit()

    # seed admin if not exists
    cur.execute("SELECT id FROM users WHERE username=?", ("admin",))
    if not cur.fetchone():
        pwd = generate_password_hash("admin123")
        cur.execute("INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?,?,?,?,?)",
                    ("admin", "admin@example.com", pwd, "admin", datetime.datetime.utcnow().isoformat()))
        con.commit()
    con.close()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def current_user():
    if "user_id" not in session:
        return None
    con = get_db()
    user = con.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    con.close()
    return user

def log_action(user_id, action, meta=None):
    con = get_db()
    con.execute("INSERT INTO audit_log (user_id, action, meta, created_at) VALUES (?,?,?,?)",
                (user_id, action, json.dumps(meta or {}), datetime.datetime.utcnow().isoformat()))
    con.commit()
    con.close()

@app.context_processor
def inject_globals():
    return {"current_user": current_user()}

@app.route("/")
def home():
    con = get_db()
    movies = con.execute("SELECT * FROM movies ORDER BY created_at DESC").fetchall()
    con.close()
    return render_template("index.html", movies=movies)

@app.route("/movie/<int:movie_id>")
def movie_detail(movie_id):
    con = get_db()
    m = con.execute("SELECT m.*, u.username as author FROM movies m LEFT JOIN users u ON m.created_by_user_id=u.id WHERE m.id=?", (movie_id,)).fetchone()
    con.close()
    if not m:
        abort(404)
    return render_template("movie_detail.html", m=m)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        email = request.form.get("email","").strip()
        password = request.form.get("password","")
        if not username or not password:
            flash("Username and password are required", "danger")
            return redirect(url_for("register"))
        con = get_db()
        try:
            con.execute("INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?,?,?,?,?)",
                        (username, email, generate_password_hash(password), "user", datetime.datetime.utcnow().isoformat()))
            con.commit()
            # log
            uid = con.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
            log_action(uid, "register", {"username": username})
            flash("Registration successful. You can login now.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")
        finally:
            con.close()
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        con = get_db()
        user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            log_action(user["id"], "login", {"ip": request.remote_addr})
            con.execute("UPDATE users SET last_login_at=?, last_ip=? WHERE id=?", 
                        (datetime.datetime.utcnow().isoformat(), request.remote_addr, user["id"]))
            con.commit()
            con.close()
            flash("Welcome back!", "success")
            return redirect(url_for("home"))
        con.close()
        flash("Invalid credentials.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    uid = session.get("user_id")
    session.clear()
    if uid:
        log_action(uid, "logout")
    flash("Logged out.", "info")
    return redirect(url_for("home"))

def require_admin():
    user = current_user()
    if not user or user["role"] != "admin":
        abort(403)

@app.route("/admin")
def admin_dashboard():
    require_admin()
    con = get_db()
    users = con.execute("SELECT id, username, email, role, created_at, last_login_at FROM users ORDER BY created_at DESC").fetchall()
    logs = con.execute("SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON a.user_id=u.id ORDER BY a.created_at DESC LIMIT 100").fetchall()
    movies = con.execute("SELECT * FROM movies ORDER BY created_at DESC").fetchall()
    con.close()
    return render_template("admin.html", users=users, logs=logs, movies=movies)

@app.route("/movie/add", methods=["GET","POST"])
def add_movie():
    require_admin()
    if request.method == "POST":
        title = request.form.get("title","").strip()
        description = request.form.get("description","").strip()
        year = request.form.get("year")
        genre = request.form.get("genre","").strip()
        video_url = request.form.get("video_url","").strip()
        poster = request.files.get("poster")
        poster_filename = None
        if poster and poster.filename and allowed_file(poster.filename):
            filename = secure_filename(poster.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            # avoid overwrite
            base, ext = os.path.splitext(filename)
            i = 1
            while os.path.exists(save_path):
                filename = f"{base}_{i}{ext}"
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                i += 1
            poster.save(save_path)
            poster_filename = filename
        con = get_db()
        con.execute("""INSERT INTO movies (title, description, year, genre, video_url, poster_filename, created_by_user_id, created_at)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    (title, description, int(year) if year else None, genre, video_url, poster_filename, session["user_id"],
                     datetime.datetime.utcnow().isoformat()))
        con.commit()
        con.close()
        log_action(session["user_id"], "movie_add", {"title": title})
        flash("Movie added.", "success")
        return redirect(url_for("home"))
    return render_template("movie_form.html")

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

if __name__ == "__main__":
    init_db()
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
