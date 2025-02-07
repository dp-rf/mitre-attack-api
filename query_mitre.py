import sqlite3
import os

# Define database path
DB_PATH = os.path.join(os.path.dirname(__file__), "mitre_attack.db")

# Function to search for TTPs by name or ID
def search_ttp(query):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Try searching by TTP ID (e.g., T1566.001)
    cursor.execute("SELECT * FROM techniques WHERE id = ?", (query,))
    result = cursor.fetchone()

    # If no result, search by name (e.g., "PowerShell")
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
        return {"error": "TTP not found in database"}

# Test function
if __name__ == "__main__":
    query = input("Enter a TTP ID or keyword (e.g., PowerShell, T1059.001): ")
    print(search_ttp(query))

