-- For those who wish to set up the database manually, here is a sample SQL script
CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    fee_paid BOOLEAN DEFAULT 0
);

CREATE TABLE bus (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    route TEXT NOT NULL,
    seats_total INTEGER NOT NULL,
    seats_available INTEGER NOT NULL,
    driver_name TEXT NOT NULL,
    driver_phone TEXT NOT NULL,
    timing TEXT NOT NULL,
    latitude REAL DEFAULT 0.0,
    longitude REAL DEFAULT 0.0
);

CREATE TABLE booking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER,
    bus_id INTEGER,
    seat_number INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(student_id) REFERENCES user(id),
    FOREIGN KEY(bus_id) REFERENCES bus(id)
);
