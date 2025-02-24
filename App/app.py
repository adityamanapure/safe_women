from flask import Flask, render_template, request, redirect, url_for, session, Response
import cv2
import os
import torch
from ultralytics import YOLO
from functools import wraps
import threading
import time

app = Flask(__name__)
app.secret_key = 'safe_women' 



users = {
    'admin': 'password'
}

# Dictionary to store the camera feeds and their detection status
camera_feeds = {}
detection_status = {}
alerts = []

# Load YOLO model
try:
    model_path = "models/yolo11_assault.pt"
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

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('home'))
        else:
            error = 'Invalid credentials. Please try again.'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        feed_name = request.form['feed_name']
        feed_url = request.form['feed_url']
        
        
        camera_feeds[feed_name] = feed_url
        detection_status[feed_name] = False
        
        return redirect(url_for('home'))
    
    return render_template('home.html', camera_feeds=camera_feeds)

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
    print(f"Fetching alerts: {alerts[-10:]}")  # Add logging to check alerts
    return {"alerts": alerts[-10:]}  # Return last 10 alerts

@app.route('/live_feed')
@login_required
def live_feed():
    return render_template('live_feed.html', camera_feeds=camera_feeds)

@app.route('/clear_alerts')
@login_required
def clear_alerts():
    global alerts
    alerts = []
    print("Alerts cleared")  # Add logging to check if alerts are cleared
    return redirect(url_for('live_feed'))

if __name__ == '__main__':
    # Create templates directory if it doesn't exist
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    app.run(debug=True, threaded=True)