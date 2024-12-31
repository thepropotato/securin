import sqlite3

def create_database():
    conn = sqlite3.connect('cve_data.db')
    cursor = conn.cursor()

    # Create table for CVE data
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            identifier TEXT,
            published_date TEXT,
            last_modified_date TEXT,
            status TEXT,
            description TEXT,
            cvss_metrics TEXT,
            cpe_criteria TEXT,
            cpe_match_criteria_id TEXT,
            cpe_vulnerable BOOLEAN
        );
    ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_database()
    print("Database and table created successfully.")
