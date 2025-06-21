import os
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy # Import SQLAlchemy

app = Flask(__name__)

# --- START OF HARDCODED DATABASE URL (FOR TESTING/DEMO ONLY) ---
# ABSOLUTELY DO NOT USE THIS IN PRODUCTION!
# Replace with your actual PostgreSQL connection details for testing.
# Format: "postgresql://username:password@host:port/database_name"
DATABASE_URL = "postgresql://db_9thcut_vora_user:8EbfvH6E70yYue0KRSqb3KebXKCq1e61@dpg-d182v1qdbo4c73d819t0-a/db_9thcut_vora"

# Configure Flask-SQLAlchemy to use the hardcoded URL
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Suppress a warning

db = SQLAlchemy(app) # Initialize SQLAlchemy with your Flask app

print(f"--- WARNING: Using hardcoded database URL (FOR TESTING ONLY): {DATABASE_URL[:40]}... ---")
# --- END OF HARDCODED DATABASE URL ---

CORS(app) # Enable CORS for all origins (for testing)

# Define the User model for SQLAlchemy
class User(db.Model):
    __tablename__ = 'users' # Explicitly name the table

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False) # Increased length for hashes

    def __repr__(self):
        return f'<User {self.username}>'

    # Helper methods for password hashing and checking
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@app.before_request
def create_tables():
    """
    Creates database tables defined by SQLAlchemy models before the first request.
    This ensures the 'users' table exists.
    """
    db.create_all()

@app.route('/signup', methods=['POST'])
def signup():
    """
    Handles user signup requests using SQLAlchemy.
    - Requires username, email, and password.
    - Prevents duplicate email registrations.
    - Hashes passwords.
    """
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'Missing username, email, or password'}), 400

    # Check if email already exists using SQLAlchemy query
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'Email already registered'}), 409

    # Create new User object and set password
    new_user = User(username=username, email=email)
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        db.session.rollback() # Rollback in case of error
        return jsonify({'message': f'Database error during signup: {e}'}), 500

@app.route('/login', methods=['POST'])
def login():
    """
    Handles user login requests using SQLAlchemy.
    - Requires email and password.
    - Verifies credentials.
    """
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Missing email or password'}), 400

    # Find user by email using SQLAlchemy query
    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        return jsonify({'message': 'Login successful', 'username': user.username}), 200
    else:
        return jsonify({'message': 'Invalid email or password'}), 401

if __name__ == '__main__':
    # Ensure tables are created when running locally
    with app.app_context():
        db.create_all()
    app.run(debug=True)
