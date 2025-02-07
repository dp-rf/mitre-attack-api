from fastapi import FastAPI, HTTPException
import sqlite3
import os

app = FastAPI()

# Define database path
DB_PATH = os.path.join(os.path.dirname(__file__), "mitre_attack.db")

# API Endpoint: Search for a TTP by ID or Name
@app.get("/search_ttp/")
def search_ttp(query: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Search by TTP ID (e.g., T1059.001)
    cursor.execute("SELECT * FROM techniques WHERE id = ?", (query,))
    result = cursor.fetchone()

    # If no result, search by name (e.g., PowerShell)
    if not result:
        cursor.execute("SELECT * FROM techniques WHERE name LIKE ?", ('%' + query + '%',))
        result = cursor.fetchone()

    conn.close()

    if result:
        return {
            "id": result[0],
            "name": result[1],
            "description": result[2],
            "tactics": result[3],
            "framework": result[4]
        }
    else:
        raise HTTPException(status_code=404, detail="TTP not found in database")

# Test API Homepage
@app.get("/")
def home():
    return {"message": "MITRE ATT&CK TTP API is running!"}

