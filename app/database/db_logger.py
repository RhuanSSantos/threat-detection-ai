from app.database.database import connect_db
from datetime import datetime


def save_detection(
    src_ip,
    dst_ip,
    prediction,
    severity,
    risk_score,
    alerts
):

    conn = connect_db()

    cursor = conn.cursor()

    cursor.execute("""

        INSERT INTO detections (

            timestamp,
            src_ip,
            dst_ip,
            prediction,
            severity,
            risk_score,
            alerts

        )

        VALUES (?, ?, ?, ?, ?, ?, ?)

    """, (

        datetime.now().strftime("%H:%M:%S"),
        src_ip,
        dst_ip,
        prediction,
        severity,
        risk_score,
        alerts

    ))

    conn.commit()

    conn.close()