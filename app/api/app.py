from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from app.database.database import connect_db

import csv
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================
# ROTAS PRINCIPAIS
# =========================================

@app.get("/")
def root():

    return {
        "message": "Threat Detection AI API Online"
    }


@app.get("/login")
def fake_login():

    return {
        "status": "login page"
    }


@app.get("/health")
def health():

    return {
        "status": "online"
    }


# =========================================
# LOGS SQLITE
# =========================================

@app.get("/logs")
def get_logs():

    conn = connect_db()

    cursor = conn.cursor()

    cursor.execute("""

        SELECT *
        FROM detections
        ORDER BY id DESC
        LIMIT 100

    """)

    rows = cursor.fetchall()

    conn.close()

    logs = []

    for row in rows:

        logs.append({

            "timestamp": row["timestamp"],
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "prediction": row["prediction"],
            "severity": row["severity"],
            "risk_score": row["risk_score"],
            "alerts": row["alerts"]

        })

    return {
        "logs": logs
    }


# =========================================
# EXPORT CSV
# =========================================

@app.get("/export/csv")
def export_csv():

    conn = connect_db()

    cursor = conn.cursor()

    cursor.execute("""

        SELECT *
        FROM detections

    """)

    rows = cursor.fetchall()

    conn.close()

    os.makedirs("exports", exist_ok=True)

    export_path = "exports/detections_export.csv"

    with open(

        export_path,
        "w",
        newline="",
        encoding="utf-8"

    ) as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([

            "timestamp",
            "src_ip",
            "dst_ip",
            "prediction",
            "severity",
            "risk_score",
            "alerts"

        ])

        for row in rows:

            writer.writerow([

                row["timestamp"],
                row["src_ip"],
                row["dst_ip"],
                row["prediction"],
                row["severity"],
                row["risk_score"],
                row["alerts"]

            ])

    return FileResponse(

        export_path,
        media_type="text/csv",
        filename="detections_export.csv"
    )