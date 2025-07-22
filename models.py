from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime

db = SQLAlchemy()
bcrypt = Bcrypt()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' or 'student'
    fee_paid = db.Column(db.Boolean, default=False)

    # New student details
    age = db.Column(db.Integer)
    student_class = db.Column(db.String(20))
    section = db.Column(db.String(10))
    admission_number = db.Column(db.String(50))
    aadhar_number = db.Column(db.String(20))
    parent_mobile = db.Column(db.String(15))

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


class Bus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    route = db.Column(db.String(150), nullable=False)
    seats_total = db.Column(db.Integer, nullable=False)
    seats_available = db.Column(db.Integer, nullable=False)
    driver_name = db.Column(db.String(100), nullable=False)
    driver_phone = db.Column(db.String(20), nullable=False)
    timing = db.Column(db.String(50), nullable=False)
    latitude = db.Column(db.Float, default=0.0)
    longitude = db.Column(db.Float, default=0.0)


class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bus_id = db.Column(db.Integer, db.ForeignKey('bus.id'), nullable=False)
    seat_number = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

    student = db.relationship('User', backref='bookings')
    bus = db.relationship('Bus', backref='bookings')


class BookingHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    bus_id = db.Column(db.Integer, db.ForeignKey('bus.id'), nullable=False)
    seat_number = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
    ended_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="Completed")  # Completed, Cancelled, Expired

    student = db.relationship('User', backref='booking_history')
    bus = db.relationship('Bus', backref='booking_history')
