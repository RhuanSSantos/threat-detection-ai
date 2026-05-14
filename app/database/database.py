import sqlite3
import os

DB_PATH = "database/threat_detection.db"


def connect_db():

    os.makedirs("database", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    conn.execute("""

        CREATE TABLE IF NOT EXISTS detections (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            src_ip TEXT,

            dst_ip TEXT,

            prediction TEXT,

            severity TEXT,

            risk_score INTEGER,

            alerts TEXT
        )

    """)

    conn.commit()

    return conn