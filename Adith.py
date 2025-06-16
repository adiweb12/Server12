import os
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy # Import Flask-SQLAlchemy

# Initialize Flask application
app = Flask(__name__)

# --- Configuration ---
# Get SECRET_KEY from environment variables for production
# For local development, you can set it in a .env file or use a fallback.
# IMPORTANT: In production, ensure this is a strong, truly random key
# set as an environment variable on Render (e.g., in Settings -> Environment)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_for_development_only')

# ⚠️⚠️ CRITICAL SECURITY WARNING: DATABASE URL HARDCODED ⚠️⚠️
# THIS IS HIGHLY INSECURE AND SHOULD NEVER BE USED IN PRODUCTION OR PUBLIC REPOSITORIES.
# Replace this with your actual Render Internal Database URL.
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://db_9thcut_user:ZTWfNofzL5K3XorzGXslvGItYZ1qorZI@dpg-d17ng5ruibrs73ftbmg0-a/db_9thcut"
# ⚠️⚠️ END OF CRITICAL SECURITY WARNING ⚠️⚠️

# This setting suppresses a warning about tracking object modifications.
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy with the Flask app
db = SQLAlchemy(app)

# --- CORS Configuration ---
# IMPORTANT: Replace 'https://9thcutstudios.netlify.app' with your actual Netlify frontend URL.
# This explicitly allows requests from your Netlify domain.
# For local development, you might temporarily use CORS(app) to allow all origins,
# but it's best to be specific in production.
CORS(app, resources={r"/*": {"origins": "https://9thcutstudios.netlify.app"}})

# --- Define your User model (SQLAlchemy ORM) ---
class User(db.Model):
    __tablename__ = 'users' # Explicitly set table name

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # 💥 FIXED: Increased length for password_hash to accommodate scrypt hashes
    password_hash = db.Column(db.String(256), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# --- Database Initialization ---
# This function creates the database tables based on your SQLAlchemy models.
# It runs when your app starts on Render via Gunicorn.
def init_db():
    with app.app_context(): # Ensures we're in the Flask application context
        db.create_all() # Creates tables for all models (like 'User') that don't exist
        print("Database tables created/ensured.")

# Call init_db() on app startup
with app.app_context():
    init_db()

# --- Route Definitions ---

@app.route('/')
def home():
    """
    A simple root endpoint to confirm the API is running.
    """
    return jsonify({'message': 'Welcome to the 9th Cut Studios API!'}), 200

@app.route('/signup', methods=['POST'])
def signup():
    """
    Handles user registration.
    Expects JSON data with username, email, password, and confirm_password.
    """
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    # Basic server-side validation
    if not all([username, email, password, confirm_password]):
        return jsonify({'message': 'All fields are required!'}), 400

    if password != confirm_password:
        return jsonify({'message': 'Passwords do not match!'}), 400

    if len(password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters long!'}), 400

    # Hash the password securely
    hashed_password = generate_password_hash(password)

    try:
        # Check for existing user
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            return jsonify({'message': 'Username or email already exists. Please choose another.'}), 409

        # Create and save new user
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully!'}), 201
    except Exception as e:
        db.session.rollback()
        print(f"Error during signup: {e}")
        return jsonify({'message': f'An unexpected server error occurred. Please try again later.'}), 500

@app.route('/login', methods=['POST'])
def login():
    """
    Handles user login.
    Expects JSON data with email and password.
    """
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({'message': 'Email and password are required!'}), 400

    # Find user by email
    user = User.query.filter_by(email=email).first()

    # Check password
    if user and check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Login successful!', 'username': user.username}), 200
    else:
        return jsonify({'message': 'Invalid email or password.'}), 401

# No app.run() for Render deployment
