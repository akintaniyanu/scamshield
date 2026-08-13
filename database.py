import sqlite3

DATABASE = "scamshield.db"


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_type TEXT NOT NULL,
            input_value TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            reasons TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


def save_scan(input_type, input_value, risk_level, risk_score, reasons):
    connection = get_connection()

    connection.execute("""
        INSERT INTO scans
        (input_type, input_value, risk_level, risk_score, reasons)
        VALUES (?, ?, ?, ?, ?)
    """, (
        input_type,
        input_value,
        risk_level,
        risk_score,
        reasons
    ))

    connection.commit()
    connection.close()

def get_scans(limit=50):

    connection = get_connection()

    scans = connection.execute("""
        SELECT *
        FROM scans
        ORDER BY created_at DESC
        LIMIT ?
    """, (limit,)).fetchall()

    connection.close()

    return scans

def get_statistics():

    connection = get_connection()

    total = connection.execute("""
        SELECT COUNT(*) AS count
        FROM scans
    """).fetchone()["count"]

    high = connection.execute("""
        SELECT COUNT(*) AS count
        FROM scans
        WHERE risk_level = 'HIGH RISK'
    """).fetchone()["count"]

    suspicious = connection.execute("""
        SELECT COUNT(*) AS count
        FROM scans
        WHERE risk_level = 'SUSPICIOUS'
    """).fetchone()["count"]

    low = connection.execute("""
        SELECT COUNT(*) AS count
        FROM scans
        WHERE risk_level = 'LOW RISK'
    """).fetchone()["count"]

    connection.close()

    return {
        "total": total,
        "high": high,
        "suspicious": suspicious,
        "low": low
    }
