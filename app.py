from flask import Flask, render_template, request, redirect, url_for, session, Response, flash
import cv2
import os
import torch
from ultralytics import YOLO
from functools import wraps
import threading
import time
import hashlib
import re
import mysql.connector
from mysql.connector import pooling

app = Flask(__name__)
app.secret_key = 'safe_women'  # Change this to a random string in production

# MySQL Configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  # Change this to your MySQL password
    'database': 'safe_women',
    'port': 3306
}


def initialize_db():
    """Create database and tables if they don't exist"""
    try:
        # First connect without specifying database to create it if it doesn't exist
        connection = mysql.connector.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            port=DB_CONFIG['port']
        )
        cursor = connection.cursor()
        
        # Create database if it doesn't exist
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
        cursor.execute(f"USE {DB_CONFIG['database']}")
        
        # Create users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username VARCHAR(50) PRIMARY KEY,
            password VARCHAR(256) NOT NULL,
            role VARCHAR(10) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Check if admin user exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        admin_count = cursor.fetchone()[0]
        
        # Create admin user if it doesn't exist
        if admin_count == 0:
            admin_password = hashlib.sha256('password'.encode()).hexdigest()
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                ('admin', admin_password, 'admin')
            )
            print("✅ Default admin user created")
        
        connection.commit()
        cursor.close()
        connection.close()
        print("✅ Database initialized successfully")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        raise


# Create MySQL connection pool
try:
    connection_pool = pooling.MySQLConnectionPool(
        pool_name="safe_women_pool",
        pool_size=5,
        **DB_CONFIG
    )
    print("✅ MySQL connection pool created successfully")
    
    # Initialize database if it doesn't exist
    initialize_db()
except Exception as e:
    print(f"❌ Error creating MySQL connection pool: {e}")
    connection_pool = None

def initialize_db():
    """Initialize database tables if they don't exist"""
    connection = get_connection()
    cursor = connection.cursor()
    
    # Create users table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username VARCHAR(50) PRIMARY KEY,
        password VARCHAR(256) NOT NULL,
        role VARCHAR(10) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Check if admin user exists, create if not
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    admin_exists = cursor.fetchone()
    
    if not admin_exists:
        # Create a default admin account
        admin_password = hashlib.sha256('password'.encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
            ('admin', admin_password, 'admin')
        )
        print("✅ Default admin user created")
    
    connection.commit()
    cursor.close()
    connection.close()

def get_connection():
    """Get a connection from the pool"""
    if connection_pool:
        return connection_pool.get_connection()
    raise Exception("Database connection pool not available")

# Dictionary to store the camera feeds and their detection status
camera_feeds = {}
detection_status = {}
alerts = []

# Load YOLO model
try:
    model_path = "models\yolo11_assault.pt"
    model = YOLO(model_path)
    print(f"🔍 YOLO model loaded from {model_path}")
except Exception as e:
    print(f"❌ Error loading YOLO model: {e}")
    model = None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        
        try:
            connection = get_connection()
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT role FROM users WHERE username = %s", (session['username'],))
            user = cursor.fetchone()
            cursor.close()
            connection.close()
            
            if not user or user['role'] != 'admin':
                flash('Admin access required for this page', 'error')
                return redirect(url_for('home'))
                
            return f(*args, **kwargs)
        except Exception as e:
            flash(f'Database error: {str(e)}', 'error')
            return redirect(url_for('home'))
            
    return decorated_function

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            connection = get_connection()
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            cursor.close()
            connection.close()
            
            if user and user['password'] == hashlib.sha256(password.encode()).hexdigest():
                session['username'] = username
                session['role'] = user['role']
                return redirect(url_for('home'))
            else:
                error = 'Invalid credentials. Please try again.'
        except Exception as e:
            error = f'Database error: {str(e)}'
    
    return render_template('login.html', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Form validation
        if len(username) < 4:
            error = 'Username must be at least 4 characters long.'
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            error = 'Username can only contain letters, numbers, and underscores.'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters long.'
        elif password != confirm_password:
            error = 'Passwords do not match.'
        else:
            try:
                connection = get_connection()
                cursor = connection.cursor()
                
                # Check if username exists
                cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
                user_exists = cursor.fetchone()
                
                if user_exists:
                    error = 'Username already exists. Please choose another one.'
                else:
                    # Add new user
                    hashed_password = hashlib.sha256(password.encode()).hexdigest()
                    cursor.execute(
                        "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                        (username, hashed_password, 'user')
                    )
                    connection.commit()
                    
                    # Set success message
                    flash('Account created successfully! You can now log in.', 'success')
                    
                    cursor.close()
                    connection.close()
                    return redirect(url_for('login'))
                
                cursor.close()
                connection.close()
            except Exception as e:
                error = f'Database error: {str(e)}'
    
    return render_template('signup.html', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        feed_name = request.form['feed_name']
        feed_url = request.form['feed_url']
        
        # Add to the camera feeds dictionary
        camera_feeds[feed_name] = feed_url
        detection_status[feed_name] = False
        
        return redirect(url_for('home'))
    
    return render_template('home.html', camera_feeds=camera_feeds, role=session.get('role', 'user'))

@app.route('/users')
@admin_required
def manage_users():
    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT username, role, created_at FROM users")
        users = cursor.fetchall()
        cursor.close()
        connection.close()
        return render_template('users.html', users=users)
    except Exception as e:
        flash(f'Database error: {str(e)}', 'error')
        return redirect(url_for('home'))

@app.route('/users/delete/<username>', methods=['POST'])
@admin_required
def delete_user(username):
    if username == 'admin':
        flash('Cannot delete the admin account', 'error')
        return redirect(url_for('manage_users'))
        
    if username == session['username']:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('manage_users'))
    
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute("DELETE FROM users WHERE username = %s", (username,))
        connection.commit()
        cursor.close()
        connection.close()
        
        flash(f'User {username} deleted successfully', 'success')
    except Exception as e:
        flash(f'Database error: {str(e)}', 'error')
    
    return redirect(url_for('manage_users'))

@app.route('/users/change_role/<username>', methods=['POST'])
@admin_required
def change_role(username):
    if username == 'admin':
        flash('Cannot change the role of the admin account', 'error')
        return redirect(url_for('manage_users'))
        
    role = request.form.get('role')
    if role not in ['admin', 'user']:
        flash('Invalid role', 'error')
        return redirect(url_for('manage_users'))
    
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute("UPDATE users SET role = %s WHERE username = %s", (role, username))
        connection.commit()
        cursor.close()
        connection.close()
        
        flash(f'Role for {username} updated to {role}', 'success')
    except Exception as e:
        flash(f'Database error: {str(e)}', 'error')
    
    return redirect(url_for('manage_users'))

def generate_frames(feed_name):
    feed_url = camera_feeds[feed_name]
    cap = cv2.VideoCapture(feed_url)
    
    if not cap.isOpened():
        print(f"❌ Error: Could not open video source: {feed_url}")
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + b'\r\n')
        return
    
    print(f"🔍 Starting detection for feed: {feed_name}")
    
    while True:
        success, frame = cap.read()
        if not success:
            # Try to reopen the connection in case of network issues
            cap = cv2.VideoCapture(feed_url)
            if not cap.isOpened():
                break
            continue
            
        # Apply YOLO assault detection if model is loaded
        if model is not None:
            results = model(frame)
            assault_detected = False
            
            for result in results:
                boxes = result.boxes
                for box in boxes:
                    x1, y1, x2, y2 = map(int, box.xyxy[0])  # Get bounding box coordinates
                    label = result.names[int(box.cls[0])]  # Get class name
                    confidence = float(box.conf[0])  # Get confidence score
                    
                    if (label != "People" and label != "Police") and confidence > 0.5:  
                        assault_detected = True
                        # Draw bounding box around detected assault
                        cv2.rectangle(frame, (x1, y1), (x2, y2), (0, 0, 255), 2)
                        cv2.putText(frame, f"{label}: {confidence:.2f}", (x1, y1-10), 
                                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 255), 2)
            
            # Update detection status and add alert if assault is detected
            if assault_detected and not detection_status.get(feed_name, False):
                detection_status[feed_name] = True
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                alerts.append({
                    "feed_name": feed_name,
                    "timestamp": timestamp,
                    "message": f"🚨 ALERT! Assault detected in {feed_name}!"
                })
                print(f"🚨 ALERT! Assault detected in {feed_name}!")
            elif not assault_detected:
                detection_status[feed_name] = False
            
            # Add alert indicator to frame if assault detected
            if detection_status.get(feed_name, False):
                cv2.putText(frame, "ASSAULT DETECTED", (10, 30),
                            cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 3)
                
        # Convert the frame to JPEG format for streaming
        ret, buffer = cv2.imencode('.jpg', frame)
        frame = buffer.tobytes()
        
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
    
    cap.release()
    print(f"🔴 Detection stopped for feed: {feed_name}")

@app.route('/video_feed/<feed_name>')
@login_required
def video_feed(feed_name):
    if feed_name in camera_feeds:
        return Response(generate_frames(feed_name),
                       mimetype='multipart/x-mixed-replace; boundary=frame')
    return "Feed not found", 404

@app.route('/alerts')
@login_required
def get_alerts():
    return {"alerts": alerts[-10:]}  # Return last 10 alerts

@app.route('/live_feed')
@login_required
def live_feed():
    return render_template('live_feed.html', camera_feeds=camera_feeds, role=session.get('role', 'user'))

@app.route('/clear_alerts')
@login_required
def clear_alerts():
    global alerts
    alerts = []
    return redirect(url_for('live_feed'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    error = None
    success = None
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        try:
            connection = get_connection()
            cursor = connection.cursor(dictionary=True)
            
            # Get current user
            cursor.execute("SELECT password FROM users WHERE username = %s", (session['username'],))
            user = cursor.fetchone()
            
            # Check if current password is correct
            if not user or user['password'] != hashlib.sha256(current_password.encode()).hexdigest():
                error = 'Current password is incorrect.'
            elif len(new_password) < 6:
                error = 'New password must be at least 6 characters long.'
            elif new_password != confirm_password:
                error = 'New passwords do not match.'
            else:
                # Update password
                hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
                cursor.execute(
                    "UPDATE users SET password = %s WHERE username = %s", 
                    (hashed_password, session['username'])
                )
                connection.commit()
                success = 'Password changed successfully!'
            
            cursor.close()
            connection.close()
        except Exception as e:
            error = f'Database error: {str(e)}'
    
    return render_template('change_password.html', error=error, success=success)

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    app.run(debug=True, threaded=True)