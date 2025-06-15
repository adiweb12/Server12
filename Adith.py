import os
from flask import Flask, request, jsonify, g # Import 'g' for application context
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from flask_cors import CORS # Ensure this is imported

app = Flask(__name__)

# --- Configuration ---
# Generate a good secret key for production and store it securely (e.g., environment variable)
# For development, os.urandom(24) is okay, but don't commit it to version control.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))

# SQLite database file path
DATABASE = 'database.db'

# --- CORS Configuration ---
# IMPORTANT: For production, replace 'http://127.0.0.1:YOUR_FRONTEND_PORT'
# with the *actual origin* (domain and port) where your frontend is served.
# If you are opening index.html directly from your file system (file://),
# the origin will be 'null'. While `CORS(app)` with no arguments works for `null`
# and `*`, it's generally best to be explicit or use a proper web server for frontend.
# For simplicity in development, CORS(app) allows all origins.
CORS(app) # Enables CORS for all routes and origins

# --- Database Connection Management ---
def get_db():
    """Establishes a database connection if one is not already present for the current request."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # Access columns by name
    return g.db

@app.teardown_appcontext
def close_db(exception):
    """Closes the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database schema."""
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
            db.rollback() # Ensure rollback on failure


# --- Route Definitions ---

@app.route('/signup', methods=['POST'])
def signup():
    # Ensure the request body is JSON
    if not request.is_json:
        return jsonify({'message': 'Request must be JSON'}), 400

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    # Basic server-side validation
    if not all([username, email, password, confirm_password]):
        return jsonify({'message': 'All fields (username, email, password, confirm_password) are required!'}), 400

    if password != confirm_password:
        return jsonify({'message': 'Passwords do not match!'}), 400

    if len(password) < 6:
        return jsonify({'message': 'Password must be at least 6 characters long!'}), 400

    # Hash the password securely
    hashed_password = generate_password_hash(password)

    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, hashed_password)
        )
        db.commit()
        return jsonify({'message': 'User registered successfully!'}), 201 # 201 Created
    except sqlite3.IntegrityError:
        # This error occurs if username or email is not unique (due to UNIQUE constraint)
        db.rollback() # Rollback the transaction on error
        return jsonify({'message': 'Username or email already exists. Please choose another.'}), 409 # 409 Conflict
    except Exception as e:
        # Catch any other unexpected errors during database operation
        db.rollback() # Always rollback on error
        print(f"Error during signup: {e}") # Log the error on the server side
        return jsonify({'message': f'An unexpected server error occurred: {str(e)}'}), 500 # 500 Internal Server Error


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
    # db.close() # No need to close here, @app.teardown_appcontext will handle it

    if user and check_password_hash(user['password_hash'], password):
        # In a real application, you would set up a session here or issue a JWT.
        # For simplicity, we just return a success message.
        return jsonify({'message': 'Login successful!', 'username': user['username']}), 200
    else:
        # Use a generic message for security, don't indicate if email or password was wrong specifically
        return jsonify({'message': 'Invalid email or password.'}), 401 # 401 Unauthorized


# --- Application Entry Point ---
if __name__ == '__main__':
    # Initialize the database when the app starts if it doesn't exist.
    # This is fine for development. For production, use Flask-Migrate or a separate script.
    init_db()
    app.run(debug=True, host='0.0.0.0') # host='0.0.0.0' makes it accessible externally (e.g., from your phone browser)
