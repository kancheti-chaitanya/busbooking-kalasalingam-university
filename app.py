from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from config import Config
from models import db, bcrypt, User, Bus, Booking, BookingHistory
from datetime import datetime, timedelta
import threading
import time
import sqlite3
import random

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
bcrypt.init_app(app)

# ------------------------
# Database schema migration
# ------------------------
def check_and_update_schema():
    """Check if the database schema is up to date and update it if needed"""
    with app.app_context():
        try:
            # Simply recreate all tables on startup to ensure they match the models
            print("Dropping all tables to ensure schema consistency...")
            db.drop_all()
            print("Creating all tables from model definitions...")
            db.create_all()
            print("Database schema created successfully")
            
            # Set up initial data if needed
            admin_exists = User.query.filter_by(username='admin').first()
            if not admin_exists:
                print("Creating admin user...")
                admin = User(username='admin', role='admin')
                admin.set_password('admin')  # Set a default password - change this in production!
                db.session.add(admin)
                
                # Create a test admin account
                test_admin = User(username='testadmin', role='admin')
                test_admin.set_password('test123')
                db.session.add(test_admin)
                print("Test admin created (testadmin/test123)")
                
                # Create a test student account
                test_student = User(
                    username='teststudent',
                    role='student',
                    age=16,
                    student_class='10th',
                    section='A',
                    admission_number='ST2023001',
                    aadhar_number='123456789012',
                    parent_mobile='9876543210',
                    fee_paid=True
                )
                test_student.set_password('student123')
                db.session.add(test_student)
                print("Test student created (teststudent/student123)")
                
                # Create a test bus
                test_bus = Bus(
                    route='City Center to School',
                    seats_total=40,
                    seats_available=40,
                    driver_name='John Driver',
                    driver_phone='8765432109',
                    timing='7:30 AM - 4:30 PM',
                    latitude=28.7041,  # Sample coordinates for New Delhi
                    longitude=77.1025
                )
                db.session.add(test_bus)
                
                # Create another test bus to show multiple routes
                test_bus2 = Bus(
                    route='Railway Station to School',
                    seats_total=35,
                    seats_available=30,
                    driver_name='Steve Driver',
                    driver_phone='9876543210',
                    timing='8:00 AM - 5:00 PM',
                    latitude=28.6942,  # Slightly different coordinates
                    longitude=77.1534
                )
                db.session.add(test_bus2)
                print("Test buses created with sample location data")
                
                db.session.commit()
                print("Test accounts created successfully")
            
        except Exception as e:
            print(f"Error during database initialization: {e}")

# Run the schema check and update
with app.app_context():
    check_and_update_schema()

# ------------------------
# Helper functions
# ------------------------
def is_logged_in():
    return 'user_id' in session

def is_admin():
    return session.get('role') == 'admin'

def check_expired_bookings():
    """Background thread to check and expire bookings after 2 hours"""
    app_context = app.app_context()
    app_context.push()
    
    # Sleep for a moment to ensure database initialization completes first
    time.sleep(10)
    
    while True:
        try:
            # Check for expired bookings
            current_time = datetime.utcnow()
            expired_bookings = Booking.query.filter(Booking.expires_at <= current_time).all()
            
            for booking in expired_bookings:
                bus = Bus.query.get(booking.bus_id)
                if bus:
                    bus.seats_available += 1
                
                # Move to history
                history = BookingHistory(
                    student_id=booking.student_id,
                    bus_id=booking.bus_id,
                    seat_number=booking.seat_number,
                    created_at=booking.created_at,
                    ended_at=current_time,
                    status="Expired"
                )
                db.session.add(history)
                
                # Remove booking
                db.session.delete(booking)
            
            if expired_bookings:
                db.session.commit()
                print(f"Expired {len(expired_bookings)} bookings")
                
            # Check every minute
            time.sleep(60)
            
        except Exception as e:
            print(f"Error in expired booking checker: {e}")
            # Wait a bit before retrying
            time.sleep(60)

# Start the expired booking checker thread
expired_checker_thread = threading.Thread(target=check_expired_bookings, daemon=True)
expired_checker_thread.start()

# ------------------------
# Routes
# ------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash("Login successful", "success")
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for('login'))

# ------------------------
# Admin routes
# ------------------------
@app.route('/admin/dashboard')
def admin_dashboard():
    if not is_logged_in() or not is_admin():
        return redirect(url_for('login'))
        
    # Validate that the user still exists in the database
    user = User.query.get(session['user_id'])
    if user is None:
        flash("Your session has expired. Please login again.", "warning")
        session.clear()
        return redirect(url_for('login'))
        
    students = User.query.filter_by(role='student').all()
    buses = Bus.query.all()
    
    # Calculate occupancy data for the chart
    occupancy_labels = [bus.route for bus in buses] if buses else []
    occupancy_data = []
    
    for bus in buses:
        if bus.seats_total > 0:
            occupancy = ((bus.seats_total - bus.seats_available) / bus.seats_total) * 100
            occupancy_data.append(round(occupancy, 1))
        else:
            occupancy_data.append(0)
    
    return render_template('admin_dashboard.html', 
                           students=students, 
                           buses=buses, 
                           occupancy_labels=occupancy_labels, 
                           occupancy_data=occupancy_data)

@app.route('/admin/add_student', methods=['GET','POST'])
def add_student():
    if not is_logged_in() or not is_admin():
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        age = request.form['age']
        student_class = request.form['student_class']
        section = request.form['section']
        admission_number = request.form['admission_number']
        aadhar_number = request.form['aadhar_number']
        parent_mobile = request.form['parent_mobile']
        fee_paid = request.form.get('fee_paid') == 'on'

        student = User(
            username=username,
            role='student',
            age=age,
            student_class=student_class,
            section=section,
            admission_number=admission_number,
            aadhar_number=aadhar_number,
            parent_mobile=parent_mobile,
            fee_paid=fee_paid
        )
        student.set_password(password)
        db.session.add(student)
        db.session.commit()
        flash("Student added successfully", "success")
        return redirect(url_for('admin_dashboard'))
    return render_template('add_student.html')

@app.route('/admin/add_bus', methods=['GET','POST'])
def add_bus():
    if not is_logged_in() or not is_admin():
        return redirect(url_for('login'))
    if request.method == 'POST':
        route = request.form['route']
        seats_total = int(request.form['seats_total'])
        driver_name = request.form['driver_name']
        driver_phone = request.form['driver_phone']
        timing = request.form['timing']
        bus = Bus(route=route, seats_total=seats_total, seats_available=seats_total,
                  driver_name=driver_name, driver_phone=driver_phone, timing=timing)
        db.session.add(bus)
        db.session.commit()
        flash("Bus added successfully", "success")
        return redirect(url_for('admin_dashboard'))
    return render_template('add_bus.html')

@app.route('/admin/update_fee/<int:student_id>', methods=['POST'])
def update_fee(student_id):
    if not is_logged_in() or not is_admin():
        return redirect(url_for('login'))
    student = User.query.get_or_404(student_id)
    student.fee_paid = request.form.get('fee_paid') == 'on'
    db.session.commit()
    flash("Fee status updated", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/add_admin', methods=['GET','POST'])
def add_admin():
    if not is_logged_in() or not is_admin():
        return redirect(url_for('login'))
        
    # Validate that the user still exists in the database
    user = User.query.get(session['user_id'])
    if user is None:
        flash("Your session has expired. Please login again.", "warning")
        session.clear()
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists. Please choose a different username.", "danger")
            return render_template('add_admin.html')
            
        admin = User(
            username=username,
            role='admin'
        )
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        flash(f"Admin user '{username}' created successfully", "success")
        return redirect(url_for('admin_dashboard'))
        
    return render_template('add_admin.html')

@app.route('/admin/bus_simulator', methods=['GET', 'POST'])
def bus_simulator():
    if not is_logged_in() or not is_admin():
        return redirect(url_for('login'))
        
    # Validate user exists
    user = User.query.get(session['user_id'])
    if user is None:
        flash("Your session has expired. Please login again.", "warning")
        session.clear()
        return redirect(url_for('login'))
    
    buses = Bus.query.all()
    
    if request.method == 'POST':
        bus_id = int(request.form['bus_id'])
        bus = Bus.query.get_or_404(bus_id)
        
        if 'update_location' in request.form:
            # Update location with specified coordinates
            bus.latitude = float(request.form['latitude'])
            bus.longitude = float(request.form['longitude'])
            db.session.commit()
            flash(f"Location updated for {bus.route}", "success")
        
        elif 'simulate_movement' in request.form:
            # Simulate movement by adjusting coordinates slightly
            # This simulates a bus moving in a random direction
            
            # Random movement between -0.001 and 0.001 degrees (roughly 100m)
            lat_change = random.uniform(-0.001, 0.001)
            lng_change = random.uniform(-0.001, 0.001)
            
            bus.latitude += lat_change
            bus.longitude += lng_change
            db.session.commit()
            
            flash(f"Simulated movement for {bus.route}", "success")
    
    return render_template('bus_simulator.html', buses=buses)

# ------------------------
# Student routes
# ------------------------
@app.route('/user/dashboard')
def user_dashboard():
    if not is_logged_in() or session.get('role') != 'student':
        return redirect(url_for('login'))
    
    # Get the user and handle case where user doesn't exist (e.g. after database reset)
    user = User.query.get(session['user_id'])
    if user is None:
        flash("Your session has expired. Please login again.", "warning")
        session.clear()
        return redirect(url_for('login'))
        
    bookings = Booking.query.filter_by(student_id=user.id).all()
    buses = Bus.query.all()
    return render_template('user_dashboard.html', user=user, bookings=bookings, buses=buses)

@app.route('/booking/<int:bus_id>', methods=['GET', 'POST'])
def booking(bus_id):
    if not is_logged_in() or session.get('role') != 'student':
        return redirect(url_for('login'))

    # Validate user exists
    user = User.query.get(session['user_id'])
    if user is None:
        flash("Your session has expired. Please login again.", "warning")
        session.clear()
        return redirect(url_for('login'))

    bus = Bus.query.get_or_404(bus_id)
    booked_seats = [b.seat_number for b in Booking.query.filter_by(bus_id=bus.id).all()]

    existing_booking = Booking.query.filter_by(student_id=user.id).first()
    if existing_booking:
        flash("You have already booked a seat. Cancel the existing one to book a new seat.", "warning")
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        seat_number = int(request.form['seat_number'])
        if seat_number in booked_seats:
            flash("Seat already booked", "danger")
            return redirect(url_for('booking', bus_id=bus.id))
        if not user.fee_paid:
            flash("Please complete fee payment before booking.", "warning")
            return redirect(url_for('user_dashboard'))
            
        # Create booking with expiration time (2 hours from now)
        now = datetime.utcnow()
        expires_at = now + timedelta(hours=2)
        booking = Booking(
            student_id=user.id, 
            bus_id=bus.id, 
            seat_number=seat_number,
            created_at=now,
            expires_at=expires_at
        )
            
        bus.seats_available -= 1
        db.session.add(booking)
        db.session.commit()
        flash("Seat booked successfully", "success")
        return redirect(url_for('booking_confirmation', booking_id=booking.id))

    return render_template('booking.html', bus=bus, booked_seats=booked_seats)

@app.route('/booking/confirmation/<int:booking_id>')
def booking_confirmation(booking_id):
    if not is_logged_in() or session.get('role') != 'student':
        return redirect(url_for('login'))
    
    # Validate user exists
    user = User.query.get(session['user_id'])
    if user is None:
        flash("Your session has expired. Please login again.", "warning")
        session.clear()
        return redirect(url_for('login'))
        
    booking = Booking.query.get_or_404(booking_id)
    
    # Check if this booking belongs to the current user
    if booking.student_id != session.get('user_id'):
        flash("You don't have permission to view this booking", "danger")
        return redirect(url_for('user_dashboard'))
    
    # Get booking history for this user
    history = BookingHistory.query.filter_by(student_id=session.get('user_id')).order_by(BookingHistory.ended_at.desc()).limit(5).all()
    
    return render_template('booking_confirmation.html', booking=booking, history=history)

@app.route('/user/cancel_booking/<int:booking_id>', methods=['POST'])
def cancel_booking(booking_id):
    if not is_logged_in() or session.get('role') != 'student':
        return redirect(url_for('login'))
    
    # Validate user exists
    user = User.query.get(session['user_id'])
    if user is None:
        flash("Your session has expired. Please login again.", "warning")
        session.clear()
        return redirect(url_for('login'))
        
    booking = Booking.query.get_or_404(booking_id)
    if booking.student_id != session.get('user_id'):
        flash("You are not authorized to cancel this booking.", "danger")
        return redirect(url_for('user_dashboard'))
        
    bus = Bus.query.get(booking.bus_id)
    bus.seats_available += 1
    
    # Add to history before deleting
    history = BookingHistory(
        student_id=booking.student_id,
        bus_id=booking.bus_id,
        seat_number=booking.seat_number,
        created_at=booking.created_at,
        ended_at=datetime.utcnow(),
        status="Cancelled"
    )
    db.session.add(history)
    
    db.session.delete(booking)
    db.session.commit()
    flash("Booking cancelled successfully", "success")
    return redirect(url_for('user_dashboard'))

@app.route('/user/history')
def booking_history():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    # Validate user exists
    user = User.query.get(session['user_id'])
    if user is None:
        flash("Your session has expired. Please login again.", "warning")
        session.clear()
        return redirect(url_for('login'))
        
    user_id = session.get('user_id')
    history = BookingHistory.query.filter_by(student_id=user_id).order_by(BookingHistory.ended_at.desc()).all()
    return render_template('booking_history.html', history=history)

@app.route('/user/profile')
def profile():
    if not is_logged_in() or session.get('role') != 'student':
        return redirect(url_for('login'))
        
    # Validate user exists
    user = User.query.get(session['user_id'])
    if user is None:
        flash("Your session has expired. Please login again.", "warning")
        session.clear()
        return redirect(url_for('login'))
        
    return render_template('profile.html', user=user)

# ------------------------
# Live tracking
# ------------------------
@app.route('/live_tracking')
def live_tracking():
    return render_template('live_tracking.html')

@app.route('/api/bus_locations')
def bus_locations():
    buses = Bus.query.all()
    buses_data = [{
        'id': bus.id,
        'latitude': bus.latitude,
        'longitude': bus.longitude,
        'route': bus.route,
        'driver_name': bus.driver_name,
        'driver_phone': bus.driver_phone,
        'seats_available': bus.seats_available,
        'seats_total': bus.seats_total,
        'timing': bus.timing
    } for bus in buses]
    return jsonify(buses_data)

@app.route('/update_location/<int:bus_id>', methods=['GET', 'POST'])
def update_location(bus_id):
    if not is_logged_in():
        return redirect(url_for('login'))
        
    bus = Bus.query.get_or_404(bus_id)
    
    # Only admin or the driver of this bus should be allowed to update location
    if not is_admin() and session.get('username') != bus.driver_name:
        flash("You don't have permission to update this bus location", "danger")
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        if request.is_json:
            # Handle API request (JSON data)
            data = request.get_json()
            bus.latitude = data.get('latitude')
            bus.longitude = data.get('longitude')
            db.session.commit()
            return jsonify({"status": "success"})
        else:
            # Handle form submission
            bus.latitude = float(request.form['latitude'])
            bus.longitude = float(request.form['longitude'])
            db.session.commit()
            flash("Location updated successfully", "success")
            return redirect(url_for('update_location', bus_id=bus_id))
    
    return render_template('update_location.html', bus=bus)

@app.route('/driver/dashboard')
def driver_dashboard():
    if not is_logged_in():
        return redirect(url_for('login'))
    
    # For demonstration, we'll consider any non-admin and non-student as a driver
    if session.get('role') == 'admin' or session.get('role') == 'student':
        flash("Access denied", "danger")
        return redirect(url_for('index'))
    
    user = User.query.get(session['user_id'])
    buses = Bus.query.filter_by(driver_name=user.username).all()
    
    return render_template('driver_dashboard.html', user=user, buses=buses)

@app.route('/api/auto_update_location/<int:bus_id>', methods=['POST'])
def auto_update_location(bus_id):
    """API endpoint for automatic location updates (e.g. from a mobile app or GPS device)"""
    # In a production app, you'd use authentication tokens instead of session
    # Here we'll use a simple API key in the request header for demonstration
    api_key = request.headers.get('X-API-Key')
    
    if not api_key or api_key != 'YOUR_SECRET_API_KEY':  # Replace with a secure key in production
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json()
    if not data or 'latitude' not in data or 'longitude' not in data:
        return jsonify({"error": "Missing required location data"}), 400
    
    bus = Bus.query.get_or_404(bus_id)
    bus.latitude = data.get('latitude')
    bus.longitude = data.get('longitude')
    db.session.commit()
    
    return jsonify({
        "status": "success",
        "message": f"Location updated for bus {bus.route}",
        "timestamp": datetime.utcnow().isoformat()
    })

if __name__ == '__main__':
    app.run(debug=True)
