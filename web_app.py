from flask import Flask, render_template, request, redirect, url_for, jsonify
import pywall_lite
import asyncio
import os
import time

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0 # Tarayıcı önbelleğini devre dışı bırakır

@app.route('/')
def index():
    config = pywall_lite.list_blocked()
    return render_template('index.html', blocked_ips=config["blocked_ips"], blocked_ports=config["blocked_ports"], blocked_protocols=config["blocked_protocols"], rules = config["rules"])

@app.route('/add_ip', methods=['POST'])
def add_ip():
    ip = request.form['ip']
    pywall_lite.add_blocked_ip(ip)
    return redirect(url_for('index'))

@app.route('/remove_ip', methods=['POST'])
def remove_ip():
    ip = request.form['ip']
    pywall_lite.remove_blocked_ip(ip)
    return redirect(url_for('index'))

@app.route('/add_port', methods=['POST'])
def add_port():
    port = int(request.form['port'])
    pywall_lite.add_blocked_port(port)
    return redirect(url_for('index'))

@app.route('/remove_port', methods=['POST'])
def remove_port():
    port = int(request.form['port'])
    pywall_lite.remove_blocked_port(port)
    return redirect(url_for('index'))

@app.route('/add_protocol', methods=['POST'])
def add_protocol():
    protocol = request.form['protocol']
    pywall_lite.add_blocked_protocol(protocol)
    return redirect(url_for('index'))

@app.route('/remove_protocol', methods=['POST'])
def remove_protocol():
    protocol = request.form['protocol']
    pywall_lite.remove_blocked_protocol(protocol)
    return redirect(url_for('index'))
    
@app.route('/add_rule', methods=['POST'])
def add_rule():
    ip = request.form['ip'] if request.form['ip'] else None
    port = int(request.form['port']) if request.form['port'] else None
    protocol = request.form['protocol'] if request.form['protocol'] else None
    rule = {}
    if ip:
        rule["ip"] = ip
    if port:
        rule["port"] = port
    if protocol:
        rule["protocol"] = protocol
    pywall_lite.add_rule(rule)
    return redirect(url_for('index'))

@app.route('/remove_rule', methods=['POST'])
def remove_rule():
    ip = request.form['ip'] if request.form['ip'] else None
    port = int(request.form['port']) if request.form['port'] else None
    protocol = request.form['protocol'] if request.form['protocol'] else None
    rule = {}
    if ip:
      rule["ip"] = ip
    if port:
      rule["port"] = port
    if protocol:
      rule["protocol"] = protocol
    pywall_lite.remove_rule(rule)
    return redirect(url_for('index'))

@app.route('/logs')
def logs():
    log_file_path = pywall_lite.LOG_FILE
    log_content = ""
    if os.path.exists(log_file_path):
        with open(log_file_path, 'r') as f:
            log_content = f.read()
    return render_template('logs.html', logs=log_content)

@app.route('/get_new_logs')
def get_new_logs():
  """Son log kayıtlarını okuyup döndürür"""
  log_file_path = pywall_lite.LOG_FILE
  if os.path.exists(log_file_path):
    with open(log_file_path, 'r') as f:
       # Dosyanın başından değil en son okuduğumuz yerin sonundan itibaren okuyalım.
      log_content = f.read()
    return jsonify({"logs": log_content.splitlines()})
  return jsonify({"logs": []})


if __name__ == '__main__':
    HOST = "0.0.0.0"
    PORT = 12345
    
    async def main():
      await pywall_lite.start_server(HOST, PORT)

    # Firewall Server'ı Başlat
    import threading
    server_thread = threading.Thread(target=asyncio.run, args=(main(),))
    server_thread.daemon = True
    server_thread.start()

    app.run(debug=True, host='0.0.0.0', use_reloader=False)