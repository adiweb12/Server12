# Adith.py (Conceptual changes for PostgreSQL with Flask-SQLAlchemy)
import os
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy # Import Flask-SQLAlchemy

app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))

# Get the database URL from Render's environment variable (or directly if debugging)
# Render automatically injects this DB URL into your web service's environment
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Recommended to set to False

db = SQLAlchemy(app) # Initialize SQLAlchemy

# --- Define your User model (SQLAlchemy ORM) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

# --- CORS Configuration ---
CORS(app, resources={r"/*": {"origins": "https://9thcutstudios.netlify.app"}})

# --- Database Initialization (using SQLAlchemy) ---
def init_db():
    with app.app_context():
        db.create_all() # This creates all tables defined as db.Model
        print("Database tables created/ensured.")

# Call init_db() on app startup to create tables if they don't exist
# If running with gunicorn, init_db() can be called before app.run() in app.py
# or you might use Flask-Migrate for robust migrations.
# For a simple Render setup, calling it here once the app context is available on startup works.
with app.app_context():
    init_db()

# --- Route Definitions (updated to use SQLAlchemy) ---
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
        return jsonify({'message': 'All fields are required!'}), 400
    if password != confirm_password:
        return jsonify({'message': 'Passwords do not match!'}), 400
    if len(password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters long!'}), 400

    hashed_password = generate_password_hash(password)

    try:
        # Check if username or email already exists using SQLAlchemy
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            return jsonify({'message': 'Username or email already exists. Please choose another.'}), 409

        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully!'}), 201
    except Exception as e:
        db.session.rollback()
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

    # Find user by email using SQLAlchemy
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Login successful!', 'username': user.username}), 200
    else:
        return jsonify({'message': 'Invalid email or password.'}), 401

# No app.run() for Render deployment
