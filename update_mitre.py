import os
import requests
import json
import sqlite3

# Define paths
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "mitre_attack.db")
ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MOBILE_URL = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"

# Function to download and save JSON files
def download_json(url, filename):
    response = requests.get(url)
    if response.status_code == 200:
        with open(os.path.join(BASE_DIR, filename), "w", encoding="utf-8") as f:
            json.dump(response.json(), f, indent=4)
        print(f"✅ Updated: {filename}")
    else:
        print(f"❌ Failed to download {filename}")

# Function to update SQLite database
def update_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM techniques")

    for json_file, framework in [("enterprise-attack.json", "enterprise"), ("mobile-attack.json", "mobile")]:
        with open(os.path.join(BASE_DIR, json_file), "r", encoding="utf-8") as f:
            data = json.load(f)

        for obj in data["objects"]:
            if obj["type"] == "attack-pattern":
                t_id = obj["external_references"][0]["external_id"]
                name = obj["name"]
                desc = obj.get("description", "")
                tactics = ", ".join(phase["phase_name"] for phase in obj.get("kill_chain_phases", []))

                cursor.execute("INSERT OR IGNORE INTO techniques VALUES (?, ?, ?, ?, ?)", 
                               (t_id, name, desc, tactics, framework))

    conn.commit()
    conn.close()
    print("✅ MITRE ATT&CK Database Updated Successfully!")

# Run the update process
download_json(ENTERPRISE_URL, "enterprise-attack.json")
download_json(MOBILE_URL, "mobile-attack.json")
update_database()

