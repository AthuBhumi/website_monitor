from flask import Flask, render_template, request
from monitor import scan_website
from apscheduler.schedulers.background import BackgroundScheduler
from flask_socketio import SocketIO
import logging
import datetime
# Initialize Flask app
app = Flask(__name__)

# List of websites to auto-monitor
monitored_websites = ["https://tars.co.in", "https://tars.co.in"]
scan_results = []

# Set up logging for monitoring
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Example function to fetch logs from a database or file (used for manual viewing)
def get_logs_from_database():
    return scan_results  # Fetches the latest scan results

# Background monitoring function
def monitor_all_sites():
    logging.info("Monitoring all websites...")
    for site in monitored_websites:
        result = scan_website(site)
        scan_results.append(result)
        if result.get('alert'):
            logging.warning(f"[ALERT] Suspicious activity detected at {site}")

# Initialize scheduler to run the monitoring function every 10 minutes
scheduler = BackgroundScheduler()
scheduler.add_job(monitor_all_sites, 'interval', minutes=10)
scheduler.start()

# ------------------ ROUTES ------------------ #

# Home route to scan a website manually
@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    if request.method == 'POST':
        url = "https://tars.co.in"
        logging.info(f"Manual scan initiated for {url}")
        results = scan_website(url)
        scan_results.append(results)  # Append result to global list
    return render_template('index.html', results=results)

# Logs route to view scan results
@app.route('/logs')
def logs():
    logs = get_logs_from_database()  # Fetch logs (latest scans)
    return render_template('monitoring_logs.html', logs=logs)

@app.route('/analytics')
def analytics():
    last_scans = scan_results[-10:]  # Get last 10 entries

    labels = [r.get('url', 'N/A') for r in last_scans]
    load_times = [r.get('load_time', 0) for r in last_scans]
    alerts_count = [len(r.get('security_alerts', [])) for r in last_scans]
    trend_labels = ['10 AM', '11 AM', '12 PM']
    trend_values = [1.2, 1.5, 1.3]
    recent_alert = True
    recent_alert_url = "https://tars.co.in/alert-page"
    # existing data
    with open('attack_logs.txt', 'r') as f:
        suspicious_logs = f.read()
    return render_template(
        'analytics.html',
        labels=labels,
        load_times=load_times,
        alerts_count=alerts_count,
        trend_labels=trend_labels,
        trend_values=trend_values,
        recent_alert=recent_alert,
        recent_alert_url=recent_alert_url,
        suspicious_logs=suspicious_logs
    )
 
@app.route('/api/chart-data')
def chart_data():
    # Example data generation (replace with actual logic to fetch live data)
    labels = [f'{i}:00' for i in range(24)]
    load_times = [random.uniform(1.0, 3.0) for _ in range(24)]
    alerts_count = [random.randint(0, 5) for _ in range(24)]
    trend_labels = ['Hour 1', 'Hour 2', 'Hour 3', 'Hour 4']
    trend_values = [random.uniform(1.0, 3.0) for _ in range(4)]

    # Here, you should add your real data logic to get the live values
    return jsonify({
        'labels': labels,
        'load_times': load_times,
        'alerts_count': alerts_count,
        'trend_labels': trend_labels,
        'trend_values': trend_values
    })
# This will be your endpoint to emit live data
@app.route('/send_data')
def send_data():
    # Example of real-time data (replace with your actual logic)
    data = {
        'labels': ['Hour 1', 'Hour 2', 'Hour 3', 'Hour 4'],
        'load_times': [5, 8, 7, 9],
        'alerts_count': [2, 3, 1, 4]
    }
    socketio.emit('update_data', data)
    return 'Data sent to client'    

def is_suspicious(req):
    # Simple example: Detects SQL injection attempt
    payload = req.args.get('query', '')
    if any(x in payload.lower() for x in ["'", '"', "union", "select", "--", "drop"]):
        return True
    return False

@app.before_request
def monitor_requests():
    if is_suspicious(request):
        log_attack(request)

def log_attack(req):
    with open('attack_logs.txt', 'a') as f:
        f.write(f"{datetime.datetime.now()} - Suspicious Request from {req.remote_addr} to {req.path} with args {req.args}\n")

@app.before_request
def detect_suspicious_activity():
    suspicious = False
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '').lower()

    # Example suspicious user-agent detection
    if "sqlmap" in user_agent or "attack" in user_agent:
        suspicious = True

    # Log suspicious activity
    if suspicious:
        with open("attack_logs.txt", "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Suspicious Request from {ip} | UA: {user_agent}\n")
# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
