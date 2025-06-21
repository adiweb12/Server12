import os
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy # Import SQLAlchemy

app = Flask(__name__)

# --- START OF HARDCODED DATABASE URL (FOR TESTING/DEMO ONLY) ---
# >>> ABSOLUTELY DO NOT USE THIS IN PRODUCTION! <<<
# Replace with your actual PostgreSQL connection details for testing.
# Format: "postgresql://username:password@host:port/database_name"
# Example for a local PostgreSQL server:
DATABASE_URL = "postgresql://db_9thcut_vora_user:8EbfvH6E70yYue0KRSqb3KebXKCq1e61@dpg-d182v1qdbo4c73d819t0-a/db_9thcut_vora"

# If you deploy to Render and connect to a Render PostgreSQL service,
# Render automatically provides a DATABASE_URL environment variable.
# In a real production app, you would typically do:
# DATABASE_URL = os.environ.get('DATABASE_URL')

# Configure Flask-SQLAlchemy to use the defined URL
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Suppress a common warning

db = SQLAlchemy(app) # Initialize SQLAlchemy with your Flask app

print(f"--- WARNING: Using hardcoded database URL (FOR TESTING ONLY): {DATABASE_URL[:40]}... ---")
# --- END OF HARDCODED DATABASE URL ---


CORS(app) # Enable CORS for all origins (for testing). Restrict for production.

# Define the User model for SQLAlchemy
class User(db.Model):
    __tablename__ = 'users' # Explicitly name the table in the database

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False) # Increased length for hashed passwords

    def __repr__(self):
        return f'<User {self.username}>'

    # Helper methods for password hashing and checking
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# New route for the root path (GET /)
@app.route('/', methods=['GET'])
def home():
    """
    Provides a welcome message for the root URL.
    This also serves as a basic health check endpoint.
    """
    return jsonify({'message': 'Welcome to the Flask Authentication API! Use /signup and /login endpoints.'}), 200

@app.route('/signup', methods=['POST'])
def signup():
    """
    Handles user signup requests using SQLAlchemy.
    - Expects 'username', 'email', and 'password' in JSON request body.
    - Prevents duplicate email registrations.
    - Hashes passwords before storing.
    - Returns 201 on success, 400 for bad input, 409 for duplicate email, 500 for DB errors.
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
        return jsonify({'message': 'Email already registered'}), 409 # Conflict

    # Create new User object and set password
    new_user = User(username=username, email=email)
    new_user.set_password(password)

    try:
        db.session.add(new_user) # Add the new user to the session
        db.session.commit()      # Commit the transaction to the database
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        db.session.rollback() # Rollback in case of any error during commit
        print(f"Error during signup: {e}") # Log the error for debugging
        return jsonify({'message': f'Database error during signup: {e}'}), 500

@app.route('/login', methods=['POST'])
def login():
    """
    Handles user login requests using SQLAlchemy.
    - Expects 'email' and 'password' in JSON request body.
    - Returns 400 for bad input, 401 for invalid credentials, 500 for DB errors.
    - Returns 200 on successful login, including the username.
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
    # Ensure database tables are created when running app.py directly.
    # This must be done within an application context.
    with app.app_context():
        db.create_all()
    app.run(debug=True) # debug=True is for development, set to False in production
