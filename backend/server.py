from flask import Flask, request, jsonify
import sqlite3
from flask_cors import CORS
import json

app = Flask(__name__)
CORS(app, origins=["http://127.0.0.1:5500"])

DATABASE = 'cve_data.db'

def connect_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/cves/list', methods=['GET'])
def list_cves():
    conn = connect_db()
    cursor = conn.cursor()

    cve_id = request.args.get('cve_id')
    year = request.args.get('year')
    min_score = request.args.get('min_score')
    max_score = request.args.get('max_score')
    last_modified_days = request.args.get('last_modified_days')
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 10))

    offset = (page - 1) * limit

    query = "SELECT * FROM cves WHERE 1=1"
    params = []

    if cve_id:
        query += " AND cve_id = ?"
        params.append(cve_id)

    if year:
        query += " AND strftime('%Y', published_date) = ?"
        params.append(year)

    if min_score:
        query += " AND base_score >= ?"
        params.append(min_score)

    if max_score:
        query += " AND base_score <= ?"
        params.append(max_score)

    if last_modified_days:
        query += " AND last_modified_date >= date('now', ? || ' days')"
        params.append(f'-{last_modified_days}')

    query += " LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    records = cursor.fetchall()

    count_query = "SELECT COUNT(*) FROM cves WHERE 1=1"
    cursor.execute(count_query, params[:-2]) 
    total_count = cursor.fetchone()[0]

    result = []
    for row in records:
        cve_item = dict(row)
        
        if cve_item.get('descriptions'):
            cve_item['descriptions'] = json.loads(cve_item['descriptions'])

        if cve_item.get('metrics'):
            cve_item['metrics'] = json.loads(cve_item['metrics'])

        result.append(cve_item)

    conn.close()
    
    return jsonify({
        "total_records": total_count,
        "total_pages": (total_count // limit) + (1 if total_count % limit else 0),
        "data": result
    })

@app.route('/cves/record_count', methods=['GET'])
def record_count():
    conn = connect_db()
    cursor = conn.cursor()

    count_query = "SELECT COUNT(*) FROM cves"
    cursor.execute(count_query)
    total_count = cursor.fetchone()[0]

    conn.close()

    return jsonify({"total_records": total_count})

@app.route('/cves/<cve_id>', methods=['GET'])
def get_cve_detail(cve_id):
    conn = connect_db()
    cursor = conn.cursor()

    query = "SELECT * FROM cves WHERE cve_id = ?"
    cursor.execute(query, (cve_id,))
    record = cursor.fetchone()

    if record:
        cve_item = dict(record)

        if cve_item.get('description'):
            cve_item['description'] = json.loads(cve_item['description'])
        if cve_item.get('cvss_metrics'):
            cve_item['cvss_metrics'] = json.loads(cve_item['cvss_metrics'])

        return jsonify({"data": cve_item})

    else:
        return jsonify({"error": "CVE not found"}), 404

if __name__ == '__main__':
    app.run(debug=True)