from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
import ollama
import pdfplumber
import pytesseract
from PIL import Image
import os
import json
from datetime import datetime, timedelta
import uuid
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = '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'
CORS(app, supports_credentials=True)


SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = "nabilzeroone@gmail.com"  
SMTP_PASSWORD = "Nabil414"  

# Google OAuth Config
GOOGLE_CLIENT_ID = "880243945977-02q96uclkdgbkiq8sa6g7495q6gu7p1r.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"

# Database setup
DATABASE = 'nara_ai.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT,
                google_id TEXT UNIQUE,
                reset_token TEXT,
                reset_token_expiry TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS chats (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                preview TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp TIMESTAMP,
                FOREIGN KEY (chat_id) REFERENCES chats (id)
            )
        ''')
        conn.commit()
    print("Database initialized!")

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Unauthorized", "redirect": "/login"}), 401
        return f(*args, **kwargs)
    return decorated_function

# Auth routes
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")
    
    if not username or not email or not password:
        return jsonify({"error": "Semua field harus diisi"}), 400
    
    if len(password) < 6:
        return jsonify({"error": "Password minimal 6 karakter"}), 400
    
    try:
        with get_db() as conn:
            hashed_password = generate_password_hash(password)
            conn.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, hashed_password)
            )
            conn.commit()
        return jsonify({"message": "Registrasi berhasil! Silakan login"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username atau email sudah digunakan"}), 400
    except Exception as e:
        print(f"Register error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    
    if not username or not password:
        return jsonify({"error": "Username dan password harus diisi"}), 400
    
    try:
        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ? OR email = ?",
                (username, username)
            ).fetchone()
            
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                return jsonify({
                    "message": "Login berhasil",
                    "user": {
                        "id": user['id'],
                        "username": user['username'],
                        "email": user['email']
                    }
                }), 200
            else:
                return jsonify({"error": "Username atau password salah"}), 401
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logout berhasil"}), 200

@app.route("/check-auth", methods=["GET"])
def check_auth():
    if 'user_id' in session:
        return jsonify({
            "authenticated": True,
            "user": {
                "id": session['user_id'],
                "username": session['username']
            }
        }), 200
    return jsonify({"authenticated": False}), 200

# Forgot Password Routes
def send_reset_email(email, token):
    """Send password reset email"""
    try:
        reset_link = f"http://localhost:5000/reset-password.html?token={token}"
        
        msg = MIMEMultipart()
        msg['From'] = SMTP_EMAIL
        msg['To'] = email
        msg['Subject'] = "NARA AI - Reset Password"
        
        body = f"""
        Halo,
        
        Anda menerima email ini karena ada permintaan reset password untuk akun NARA AI Anda.
        
        Klik link berikut untuk reset password:
        {reset_link}
        
        Link ini akan kadaluarsa dalam 1 jam.
        
        Jika Anda tidak meminta reset password, abaikan email ini.
        
        Salam,
        Tim NARA AI
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json()
    email = data.get("email", "").strip()
    
    if not email:
        return jsonify({"error": "Email harus diisi"}), 400
    
    try:
        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            
            if user:
                # Generate reset token
                reset_token = secrets.token_urlsafe(32)
                expiry = datetime.now() + timedelta(hours=1)
                
                conn.execute(
                    "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?",
                    (reset_token, expiry.isoformat(), email)
                )
                conn.commit()
                
                # Send email
                if send_reset_email(email, reset_token):
                    return jsonify({"message": "Link reset password telah dikirim ke email Anda"}), 200
                else:
                    return jsonify({"error": "Gagal mengirim email. Coba lagi nanti."}), 500
            else:
                # Jangan kasih tau kalau email tidak ditemukan (security)
                return jsonify({"message": "Jika email terdaftar, link reset akan dikirim"}), 200
                
    except Exception as e:
        print(f"Forgot password error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json()
    token = data.get("token", "")
    new_password = data.get("password", "")
    
    if not token or not new_password:
        return jsonify({"error": "Token dan password harus diisi"}), 400
    
    if len(new_password) < 6:
        return jsonify({"error": "Password minimal 6 karakter"}), 400
    
    try:
        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE reset_token = ?",
                (token,)
            ).fetchone()
            
            if not user:
                return jsonify({"error": "Token tidak valid"}), 400
            
            # Check if token expired
            expiry = datetime.fromisoformat(user['reset_token_expiry'])
            if datetime.now() > expiry:
                return jsonify({"error": "Token sudah kadaluarsa"}), 400
            
            # Update password
            hashed_password = generate_password_hash(new_password)
            conn.execute(
                "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?",
                (hashed_password, user['id'])
            )
            conn.commit()
            
            return jsonify({"message": "Password berhasil direset"}), 200
            
    except Exception as e:
        print(f"Reset password error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/login.html", methods=["GET"])
def login_page():
    return render_template("login.html")

# Google OAuth Routes
@app.route("/auth/google", methods=["POST"])
def google_auth():
    """Handle Google OAuth login"""
    data = request.get_json()
    google_token = data.get("credential")
    
    if not google_token:
        return jsonify({"error": "Token Google tidak ditemukan"}), 400
    
    try:
        # Verify Google token
        import requests
        response = requests.get(
            f"https://oauth2.googleapis.com/tokeninfo?id_token={google_token}"
        )
        
        if response.status_code != 200:
            return jsonify({"error": "Token Google tidak valid"}), 400
        
        google_data = response.json()
        google_id = google_data.get("sub")
        email = google_data.get("email")
        name = google_data.get("name")
        
        if not google_id or not email:
            return jsonify({"error": "Data Google tidak lengkap"}), 400
        
        with get_db() as conn:
            # Check if user exists
            user = conn.execute(
                "SELECT * FROM users WHERE google_id = ? OR email = ?",
                (google_id, email)
            ).fetchone()
            
            if user:
                # Update google_id if not set
                if not user['google_id']:
                    conn.execute(
                        "UPDATE users SET google_id = ? WHERE id = ?",
                        (google_id, user['id'])
                    )
                    conn.commit()
                
                user_id = user['id']
                username = user['username']
            else:
                # Create new user
                username = email.split('@')[0]
                # Ensure unique username
                counter = 1
                original_username = username
                while conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone():
                    username = f"{original_username}{counter}"
                    counter += 1
                
                cursor = conn.execute(
                    "INSERT INTO users (username, email, google_id) VALUES (?, ?, ?)",
                    (username, email, google_id)
                )
                conn.commit()
                user_id = cursor.lastrowid
            
            # Set session
            session['user_id'] = user_id
            session['username'] = username
            
            return jsonify({
                "message": "Login berhasil",
                "user": {
                    "id": user_id,
                    "username": username,
                    "email": email
                }
            }), 200
            
    except Exception as e:
        print(f"Google auth error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Gagal login dengan Google"}), 500

# Main routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    data = request.get_json()
    message = data.get("message", "")
    chat_id = data.get("chat_id")
    user_id = session['user_id']
    
    if not message or not chat_id:
        return jsonify({"reply": "Pesan atau chat_id kosong"}), 400
    
    try:
        response = ollama.chat(model="llama3.2", messages=[
            {"role": "user", "content": message}
        ])
        reply = response['message']['content']
        
        # Save to database
        with get_db() as conn:
            # Check if chat exists
            chat = conn.execute("SELECT * FROM chats WHERE id = ? AND user_id = ?", (chat_id, user_id)).fetchone()
            
            if not chat:
                # Create new chat
                conn.execute(
                    "INSERT INTO chats (id, user_id, preview, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (chat_id, user_id, message[:50], datetime.now().isoformat(), datetime.now().isoformat())
                )
            
            # Save messages
            timestamp = datetime.now().isoformat()
            conn.execute(
                "INSERT INTO messages (chat_id, role, content, timestamp) VALUES (?, ?, ?, ?)",
                (chat_id, 'user', message, timestamp)
            )
            conn.execute(
                "INSERT INTO messages (chat_id, role, content, timestamp) VALUES (?, ?, ?, ?)",
                (chat_id, 'assistant', reply, timestamp)
            )
            
            # Update chat preview and timestamp
            conn.execute(
                "UPDATE chats SET preview = ?, updated_at = ? WHERE id = ?",
                (message[:50], timestamp, chat_id)
            )
            conn.commit()
        
        return jsonify({"reply": reply})
    except Exception as e:
        print(f"Error in /chat: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"reply": f"Maaf, ada error: {str(e)}"}), 500

@app.route("/new-chat", methods=["POST"])
@login_required
def new_chat():
    try:
        chat_id = str(uuid.uuid4())
        user_id = session['user_id']
        timestamp = datetime.now().isoformat()
        
        with get_db() as conn:
            conn.execute(
                "INSERT INTO chats (id, user_id, preview, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (chat_id, user_id, "Chat baru", timestamp, timestamp)
            )
            conn.commit()
        
        return jsonify({"chat_id": chat_id, "message": "Chat baru berhasil dibuat"})
    except Exception as e:
        print(f"Error in /new-chat: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/chat-list", methods=["GET"])
@login_required
def get_chat_list():
    try:
        user_id = session['user_id']
        with get_db() as conn:
            chats = conn.execute(
                "SELECT id, preview, created_at, updated_at FROM chats WHERE user_id = ? ORDER BY updated_at DESC",
                (user_id,)
            ).fetchall()
            
            chat_list = [dict(chat) for chat in chats]
        
        return jsonify({"chats": chat_list})
    except Exception as e:
        print(f"Error in /chat-list: {e}")
        return jsonify({"chats": []}), 500

@app.route("/chat/<chat_id>", methods=["GET"])
@login_required
def get_chat(chat_id):
    try:
        user_id = session['user_id']
        with get_db() as conn:
            chat = conn.execute(
                "SELECT * FROM chats WHERE id = ? AND user_id = ?",
                (chat_id, user_id)
            ).fetchone()
            
            if not chat:
                return jsonify({"error": "Chat tidak ditemukan"}), 404
            
            messages = conn.execute(
                "SELECT role, content, timestamp FROM messages WHERE chat_id = ? ORDER BY timestamp ASC",
                (chat_id,)
            ).fetchall()
            
            return jsonify({
                "id": chat['id'],
                "preview": chat['preview'],
                "created_at": chat['created_at'],
                "updated_at": chat['updated_at'],
                "messages": [dict(msg) for msg in messages]
            })
    except Exception as e:
        print(f"Error in /chat/<id>: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/chat/<chat_id>/rename", methods=["PUT"])
@login_required
def rename_chat(chat_id):
    try:
        data = request.get_json()
        new_name = data.get("name", "").strip()
        user_id = session['user_id']
        
        if not new_name:
            return jsonify({"error": "Nama tidak boleh kosong"}), 400
        
        with get_db() as conn:
            result = conn.execute(
                "UPDATE chats SET preview = ?, updated_at = ? WHERE id = ? AND user_id = ?",
                (new_name, datetime.now().isoformat(), chat_id, user_id)
            )
            conn.commit()
            
            if result.rowcount == 0:
                return jsonify({"error": "Chat tidak ditemukan"}), 404
        
        return jsonify({"message": "Chat berhasil direname", "new_name": new_name})
    except Exception as e:
        print(f"Error in /chat/<id>/rename: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/chat/<chat_id>", methods=["DELETE"])
@login_required
def delete_chat(chat_id):
    try:
        user_id = session['user_id']
        with get_db() as conn:
            # Delete messages first
            conn.execute("DELETE FROM messages WHERE chat_id = ?", (chat_id,))
            # Delete chat
            result = conn.execute(
                "DELETE FROM chats WHERE id = ? AND user_id = ?",
                (chat_id, user_id)
            )
            conn.commit()
            
            if result.rowcount == 0:
                return jsonify({"error": "Chat tidak ditemukan"}), 404
        
        return jsonify({"message": "Chat berhasil dihapus"})
    except Exception as e:
        print(f"Error in DELETE /chat/<id>: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    file = request.files.get("file")
    if file and file.filename.endswith(".pdf"):
        with pdfplumber.open(file) as pdf:
            text = "\n".join(page.extract_text() for page in pdf.pages if page.extract_text())
        try:
            response = ollama.chat(model="llama3:2b", messages=[
                {"role": "user", "content": f"Baca dan ringkas dokumen ini:\n{text[:3000]}"}
            ])
            reply = response['message']['content']
            return jsonify({"reply": reply})
        except Exception as e:
            return jsonify({"reply": "Gagal memproses dokumen."}), 500
    return jsonify({"reply": "File tidak didukung, hanya PDF."}), 400

@app.route("/upload-image", methods=["POST"])
@login_required
def upload_image():
    file = request.files.get("file")
    if file:
        try:
            image = Image.open(file)
            text = pytesseract.image_to_string(image)
            response = ollama.chat(model="llama3:2b", messages=[
                {"role": "user", "content": f"Aku baru aja upload gambar yang isinya:\n{text}\nJelaskan atau bantu aku pahami ini ya."}
            ])
            reply = response['message']['content']
            return jsonify({"reply": reply})
        except Exception as e:
            return jsonify({"reply": "Belom bisa upload gambar hhe."}), 500
    return jsonify({"reply": "Tidak ada gambar terdeteksi."}), 400

if __name__ == "__main__":
    init_db()
    print("="*50)
    print("NARA AI Backend Server with Authentication")
    print("="*50)
    print(f"Database: {DATABASE}")
    print("Server running on http://localhost:5000")
    print("="*50)
    app.run(debug=True)
