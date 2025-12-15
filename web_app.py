import sqlite3
from flask import Flask, jsonify, render_template_string

DB_PATH = "ids.db"
app = Flask(__name__)            #sets up app to be our Flask application object. Listens for http requests, routes them to functions, returns responses. The interface layer between the user and our program


HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Mini IDS Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; }
    h1 { margin: 0 0 8px; }
    .meta { color: #555; margin-bottom: 18px; }
    table { border-collapse: collapse; width: 100%; margin-top: 10px; }
    th, td { border: 1px solid #ddd; padding: 8px; font-size: 14px; vertical-align: top; }
    th { background: #f5f5f5; text-align: left; }
    .pill { display:inline-block; padding:2px 8px; border-radius: 999px; background:#eee; }
  </style>
</head>
<body>
  <h1>Mini IDS Dashboard</h1>
  <div class="meta">Data source: <span class="pill">SQLite (ids.db)</span></div>

  <h2>Recent Alerts</h2>
  <table>
    <thead>
      <tr>
        <th>Last Seen</th>
        <th>Type</th>
        <th>Severity</th>
        <th>Source IP</th>
        <th>Count</th>
        <th>Evidence</th>
      </tr>
    </thead>
    <tbody>
      {% for a in alerts %}
      <tr>
        <td>{{ a["ts_last"] }}</td>
        <td>{{ a["alert_type"] }}</td>
        <td>{{ a["severity"] }}</td>
        <td>{{ a["src_ip"] or "" }}</td>
        <td>{{ a["event_count"] }}</td>
        <td>{{ a["evidence"] }}</td>
      </tr>
      {% endfor %}
      {% if not alerts %}
      <tr><td colspan="6">No alerts yet. (That’s normal until thresholds trigger.)</td></tr>
      {% endif %}
    </tbody>
  </table>

  <h2>Top Offender IPs (by alerts)</h2>
  <table>
    <thead><tr><th>IP</th><th>Alerts</th></tr></thead>
    <tbody>
      {% for row in top_ips %}
      <tr><td>{{ row["src_ip"] }}</td><td>{{ row["n"] }}</td></tr>
      {% endfor %}
      {% if not top_ips %}
      <tr><td colspan="2">No IP-based alerts yet.</td></tr>
      {% endif %}
    </tbody>
  </table>

</body>
</html>
"""


def q(sql, args=()):
    conn = sqlite3.connect(DB_PATH)

    #row_factory is a field in every sqlite3.Connection object
    #sqlite3.Row is the row object type that sqlite3 will return
    conn.row_factory = sqlite3.Row              #tells sqlite, "when I fetch rows from this database, return them like dictionaries instead of tuples" (still accessible like a tuple but now also like a dictionary. Not a real dictionary though)
    cur = conn.cursor()

    cur.execute(sql, args)
    rows = cur.fetchall()           #returns each row in a list of dictionaries
    conn.close()
    return [dict(r) for r in rows]      #goes through every row object in rows and converts each one to an actual dictionary 


@app.get("/")           #tells our app when the user accesses http://my_ip/, run this function. my_ip would probably be a domain name
def index():
    alerts = q("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
    top_ips = q("""
        SELECT src_ip, COUNT(*) as n
        FROM alerts
        WHERE src_ip IS NOT NULL AND src_ip != ''
        GROUP BY src_ip
        ORDER BY n DESC
        LIMIT 20
        """)
    return render_template_string(HTML, alerts=alerts, top_ips=top_ips)

@app.get("/api/alerts")
def api_alerts():
    return jsonify(q("SELECT * FROM alerts ORDER BY id DESC LIMIT 200"))

if __name__ == "__main__":
    app.run(debug=True, port=5000)