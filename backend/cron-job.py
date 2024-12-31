import requests
import sqlite3
import time
import json

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DATABASE = "cve_data.db"

def fetch_cve_data(start_index=0, results_per_page=2000):
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page
    }
    response = requests.get(API_URL, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch data: {response.status_code}")
        return None

def save_cve_data(cve_items):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    for item in cve_items:
        cve_id = item["cve"]["id"]
        identifier = item["cve"]["sourceIdentifier"]

        descriptions = item["cve"].get("descriptions", [])
        descriptions = json.dumps(descriptions)

        published_date = item["cve"].get("published")
        last_modified_date = item["cve"].get("lastModified")
        status = item["cve"].get("vulnStatus")

        metrics_v3 = item["cve"].get("metrics", {}).get("cvssMetricV31", [])
        cvss_v3_data = {}
        if metrics_v3:
            cvss_v3_data = {
                "base_score": metrics_v3[0]["cvssData"].get("baseScore"),
                "severity": metrics_v3[0]["cvssData"].get("baseSeverity"),
                "vector_string": metrics_v3[0]["cvssData"].get("vectorString"),
                "access_vector": metrics_v3[0]["cvssData"].get("accessVector"),
                "access_complexity": metrics_v3[0]["cvssData"].get("accessComplexity"),
                "authentication": metrics_v3[0]["cvssData"].get("authentication"),
                "confidentiality_impact": metrics_v3[0]["cvssData"].get("confidentialityImpact"),
                "integrity_impact": metrics_v3[0]["cvssData"].get("integrityImpact"),
                "availability_impact": metrics_v3[0]["cvssData"].get("availabilityImpact"),
                "exploitability_score": metrics_v3[0]["cvssData"].get("exploitabilityScore"),
                "impact_score": metrics_v3[0]["cvssData"].get("impactScore")
            }

        metrics_v2 = item["cve"].get("metrics", {}).get("cvssMetricV2", [])
        cvss_v2_data = {}
        if not metrics_v3 and metrics_v2:
            cvss_v2_data = {
                "base_score": metrics_v2[0]["cvssData"].get("baseScore"),
                "severity": metrics_v2[0]["cvssData"].get("baseSeverity"),
                "vector_string": metrics_v2[0]["cvssData"].get("vectorString"),
                "access_vector": metrics_v2[0]["cvssData"].get("accessVector"),
                "access_complexity": metrics_v2[0]["cvssData"].get("accessComplexity"),
                "authentication": metrics_v2[0]["cvssData"].get("authentication"),
                "confidentiality_impact": metrics_v2[0]["cvssData"].get("confidentialityImpact"),
                "integrity_impact": metrics_v2[0]["cvssData"].get("integrityImpact"),
                "availability_impact": metrics_v2[0]["cvssData"].get("availabilityImpact"),
                "exploitability_score": metrics_v2[0]["cvssData"].get("exploitabilityScore"),
                "impact_score": metrics_v2[0]["cvssData"].get("impactScore")
            }

        cvss_metrics = {}
        if cvss_v3_data:
            cvss_metrics["cvss_v3"] = cvss_v3_data
        if cvss_v2_data:
            cvss_metrics["cvss_v2"] = cvss_v2_data

        cvss_metrics = json.dumps(cvss_metrics)

        cpe_data = item["cve"].get("configurations", {})
        cpe_data = cpe_data[0].get("nodes", []) if len(cpe_data) > 0 else []

        cpe_criteria = None
        cpe_match_criteria_id = None
        cpe_vulnerable = False

        if cpe_data:
            for node in cpe_data:
                for cpe in node.get("cpeMatch", []):
                    if cpe.get("vulnerable"):
                        cpe_criteria = cpe.get("criteria")
                        cpe_match_criteria_id = cpe.get("matchCriteriaId")
                        cpe_vulnerable = cpe.get("vulnerable")

        try:
            cursor.execute('''
                INSERT OR IGNORE INTO cves (
                    cve_id, identifier, published_date, last_modified_date, status, description,
                    cvss_metrics, cpe_criteria, cpe_match_criteria_id, cpe_vulnerable
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_id, identifier, published_date, last_modified_date, status, descriptions,
                cvss_metrics, cpe_criteria, cpe_match_criteria_id, cpe_vulnerable
            ))
        except sqlite3.Error as e:
            print(f"Database error: {e}")

    conn.commit()
    conn.close()

def periodic_sync():
    start_index = 0
    results_per_page = 2000

    while True:
        data = fetch_cve_data(start_index, results_per_page)

        if not data or not data.get("vulnerabilities"):
            print("No more data to fetch or response structure invalid.")
            break

        save_cve_data(data["vulnerabilities"])

        start_index += results_per_page
        print(f"Fetched and saved {start_index} records...")

        time.sleep(5)

if __name__ == "__main__":
    periodic_sync()