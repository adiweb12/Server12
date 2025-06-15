import os
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from flask_cors import CORS # Make sure this is imported

app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
DATABASE = 'database.db'

# --- CORS Configuration ---
# IMPORTANT: Replace 'https://9thcutstudios.netlify.app' with the exact URL of your Netlify frontend.
# If you have multiple origins (e.g., local development and Netlify), you can list them:
# origins = ["http://127.0.0.1:5000", "https://9thcutstudios.netlify.app"]
# CORS(app, resources={r"/*": {"origins": origins}})
CORS(app, resources={r"/*": {"origins": "https://9thcutstudios.netlify.app"}})

# --- Database Connection Management ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL
                )
            ''')
            db.commit()
            print("Database table 'users' ensured to exist.")
        except Exception as e:
            print(f"Error initializing database: {e}")
            db.rollback()

# --- Route Definitions ---

@app.route('/signup', methods=['POST'])
def signup():
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not all([username, email, password, confirm_password]):
        return jsonify({'message': 'All fields (username, email, password, confirm_password) are required!'}), 400

    if password != confirm_password:
        return jsonify({'message': 'Passwords do not match!'}), 400

    if len(password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters long!'}), 400

    hashed_password = generate_password_hash(password)

    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, hashed_password)
        )
        db.commit()
        return jsonify({'message': 'User registered successfully!'}), 201
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify({'message': 'Username or email already exists. Please choose another.'}), 409
    except Exception as e:
        db.rollback()
        print(f"Error during signup: {e}")
        return jsonify({'message': f'An unexpected server error occurred: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({'message': 'Email and password are required!'}), 400

    db = get_db()
    cursor = db.cursor()
    user = cursor.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if user and check_password_hash(user['password_hash'], password):
        return jsonify({'message': 'Login successful!', 'username': user['username']}), 200
    else:
        return jsonify({'message': 'Invalid email or password.'}), 401

# Removed app.run() for Render deployment
