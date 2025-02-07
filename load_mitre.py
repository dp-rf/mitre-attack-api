import json
import sqlite3
import os

# Set the correct database path
DB_PATH = os.path.join(os.path.dirname(__file__), "mitre_attack.db")

# Function to load MITRE ATT&CK JSON data into SQLite
def load_attack_data(json_file, framework):
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS techniques (
        id TEXT PRIMARY KEY,
        name TEXT,
        description TEXT,
        tactics TEXT,
        framework TEXT
    );
    """)

    for obj in data["objects"]:
        if obj["type"] == "attack-pattern":
            t_id = obj["external_references"][0]["external_id"]
            name = obj["name"]
            desc = obj.get("description", "")

            # 🛠 FIX: Check if "kill_chain_phases" exists before accessing it
            if "kill_chain_phases" in obj:
                tactics = ", ".join(phase["phase_name"] for phase in obj["kill_chain_phases"])
            else:
                tactics = "Unknown"

            cursor.execute("INSERT OR IGNORE INTO techniques VALUES (?, ?, ?, ?, ?)", 
                           (t_id, name, desc, tactics, framework))

    conn.commit()
    conn.close()

# Load both Enterprise and Mobile frameworks
BASE_DIR = os.path.dirname(__file__)
load_attack_data(os.path.join(BASE_DIR, "enterprise-attack.json"), "enterprise")
load_attack_data(os.path.join(BASE_DIR, "mobile-attack.json"), "mobile")

print("✅ MITRE ATT&CK Enterprise & Mobile data loaded successfully!")
