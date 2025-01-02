import asyncio
import socket
import logging
import json
from datetime import datetime, timedelta
from collections import defaultdict
import argparse
import os
import re  # Regex modülünü ekledik

# Ayarları saklamak için bir dosya adı
CONFIG_FILE = "pywall_config.json"
LOG_FILE = "pywall.log"

# Logging ayarları
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# DoS/DDoS koruması ayarları
MAX_CONNECTIONS_PER_MINUTE = 100
BAN_TIME = 60
connection_attempts = defaultdict(lambda: [])

def load_config():
    """Konfigürasyonu dosyadan yükler."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        config = {
            "blocked_ips": [],
            "blocked_ports": [],
            "blocked_protocols": [],
            "rules": [] # Yeni: Kuralları saklamak için liste
        }
        save_config(config)
    return config

def save_config(config):
    """Konfigürasyonu dosyaya kaydeder."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def is_ip_blocked(ip, config):
    """IP adresinin bloklanıp bloklanmadığını kontrol eder."""
    return ip in config["blocked_ips"]

def is_port_blocked(port, config):
    """Portun bloklanıp bloklanmadığını kontrol eder."""
    return port in config["blocked_ports"]

def is_protocol_blocked(protocol, config):
    """Protokolün bloklanıp bloklanmadığını kontrol eder."""
    return protocol in config["blocked_protocols"]


def is_dos_attack(ip):
    """DoS saldırısı olup olmadığını kontrol eder."""
    now = datetime.now()
    attempts = connection_attempts[ip]
    # Geçmiş bağlantı girişimlerini temizle
    connection_attempts[ip] = [attempt for attempt in attempts if attempt > now - timedelta(seconds=60)]
    
    if len(connection_attempts[ip]) >= MAX_CONNECTIONS_PER_MINUTE:
        log_event(f"Possible DoS attack from {ip}. Connection attempts exceeded limit ({MAX_CONNECTIONS_PER_MINUTE})", "WARNING", extra={"ip": ip})
        return True # Olası DoS saldırısı var
    return False # DoS saldırısı yok
    
def matches_rule(ip, port, protocol, rule):
    """Bir bağlantının kurala uyup uymadığını kontrol eder."""
    if 'ip' in rule and not re.fullmatch(rule['ip'], ip):
       return False
    if 'port' in rule and int(port) != rule['port']:
       return False
    if 'protocol' in rule and rule['protocol'] != protocol:
      return False
    return True

async def handle_connection(transport, protocol, config):
    """Gelen bağlantıyı yönetir."""
    if protocol == "tcp":
        ip, port = transport.get_extra_info('peername')
    elif protocol == "udp":
        ip, port = transport.get_extra_info('peername')[:2]
    else:
        ip = "unknown"
        port = "unknown"
    
    now = datetime.now()
    connection_attempts[ip].append(now) # Bağlantı girişimini kaydet
    
    if is_dos_attack(ip):
      log_event(f"Blocked connection from {ip}:{port} (DoS Protection)", "WARNING", extra={"ip": ip, "port":port, "protocol":protocol})
      if protocol == "tcp":
        transport.close()
      return
    
    for rule in config.get("rules", []):
         if matches_rule(ip, port, protocol, rule):
           log_event(f"Blocked connection from {ip}:{port} (Rule Blocked)", "WARNING", extra={"ip": ip, "port":port, "protocol":protocol, "rule": rule})
           if protocol == "tcp":
                transport.close()
           return
            
    if is_ip_blocked(ip, config):
        log_event(f"Blocked connection from {ip}:{port} (IP Blocked)", "WARNING", extra={"ip": ip, "port":port, "protocol":protocol})
        if protocol == "tcp":
           transport.close()
        return
    
    if is_port_blocked(port, config):
        log_event(f"Blocked connection from {ip}:{port} (Port Blocked)", "WARNING", extra={"ip": ip, "port":port, "protocol":protocol})
        if protocol == "tcp":
           transport.close()
        return
    
    if is_protocol_blocked(protocol, config):
        log_event(f"Blocked connection from {ip}:{port} (Protocol Blocked)", "WARNING", extra={"ip": ip, "port":port, "protocol":protocol})
        if protocol == "tcp":
            transport.close()
        return
    
    log_event(f"Allowed connection from {ip}:{port} (Protocol: {protocol})", "INFO", extra={"ip": ip, "port":port, "protocol":protocol})
    try:
        if protocol == "tcp":
            transport.write(b"Welcome to PyWall Lite!\n")
            transport.close()
    except Exception as e:
        log_event(f"Error handling connection from {ip}:{port}: {e}", "ERROR", extra={"ip": ip, "port":port, "protocol":protocol})

def log_event(message, level, extra=None):
    """Olayları loglar."""
    if extra is None:
        extra = {}
    if level == "INFO":
        logging.info(message, extra=extra)
    elif level == "WARNING":
        logging.warning(message, extra=extra)
    elif level == "ERROR":
        logging.error(message, extra=extra)
    else:
        logging.debug(message, extra=extra)

async def start_server(host, port):
    """Server'ı başlatır."""
    config = load_config()
    
    async def handle_tcp_client(reader, writer):
      await handle_connection(writer, "tcp", config)
    
    async def handle_udp_client(transport, data, addr):
       await handle_connection(transport, "udp", config)
    
    loop = asyncio.get_event_loop()
    
    tcp_server = await asyncio.start_server(handle_tcp_client, host, port)
    log_event(f"TCP Server listening on {host}:{port}", "INFO")

    udp_server_transport, udp_protocol = await loop.create_datagram_endpoint(
        lambda: DatagramProtocol(handle_udp_client),
        local_addr=(host, port)
    )

    log_event(f"UDP Server listening on {host}:{port}", "INFO")
        
    await asyncio.gather(
        tcp_server.serve_forever(),
        asyncio.Future()
        )
        
class DatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, handle_udp_client):
        super().__init__()
        self.handle_udp_client = handle_udp_client

    def connection_made(self, transport):
      self.transport = transport
    
    def datagram_received(self, data, addr):
      asyncio.create_task(self.handle_udp_client(self.transport, data, addr))

def add_blocked_ip(ip):
    """Bloklanan IP adreslerine IP ekler."""
    config = load_config()
    if ip not in config["blocked_ips"]:
        config["blocked_ips"].append(ip)
        save_config(config)
        log_event(f"Added IP to blocked list: {ip}", "INFO", extra={"ip": ip})
    else:
        log_event(f"IP already in blocked list: {ip}", "INFO", extra={"ip": ip})

def remove_blocked_ip(ip):
    """Bloklanan IP adreslerinden IP kaldırır."""
    config = load_config()
    if ip in config["blocked_ips"]:
        config["blocked_ips"].remove(ip)
        save_config(config)
        log_event(f"Removed IP from blocked list: {ip}", "INFO", extra={"ip": ip})
    else:
        log_event(f"IP not in blocked list: {ip}", "INFO", extra={"ip": ip})

def add_blocked_port(port):
    """Bloklanan portlara port ekler."""
    config = load_config()
    if port not in config["blocked_ports"]:
        config["blocked_ports"].append(port)
        save_config(config)
        log_event(f"Added port to blocked list: {port}", "INFO", extra={"port": port})
    else:
        log_event(f"Port already in blocked list: {port}", "INFO", extra={"port": port})

def remove_blocked_port(port):
    """Bloklanan portlardan port kaldırır."""
    config = load_config()
    if port in config["blocked_ports"]:
        config["blocked_ports"].remove(port)
        save_config(config)
        log_event(f"Removed port from blocked list: {port}", "INFO", extra={"port": port})
    else:
        log_event(f"Port not in blocked list: {port}", "INFO", extra={"port": port})

def add_blocked_protocol(protocol):
    """Bloklanan protokollere protokol ekler."""
    config = load_config()
    if protocol not in config["blocked_protocols"]:
        config["blocked_protocols"].append(protocol)
        save_config(config)
        log_event(f"Added protocol to blocked list: {protocol}", "INFO", extra={"protocol": protocol})
    else:
        log_event(f"Protocol already in blocked list: {protocol}", "INFO", extra={"protocol": protocol})
        
def remove_blocked_protocol(protocol):
    """Bloklanan protokollerden protokol kaldırır."""
    config = load_config()
    if protocol in config["blocked_protocols"]:
        config["blocked_protocols"].remove(protocol)
        save_config(config)
        log_event(f"Removed protocol from blocked list: {protocol}", "INFO", extra={"protocol": protocol})
    else:
        log_event(f"Protocol not in blocked list: {protocol}", "INFO", extra={"protocol": protocol})

def list_blocked():
    """Bloklanan IP, port ve protokolleri listeler"""
    config = load_config()
    log_event(f"Blocked IPs: {config['blocked_ips']}", "INFO", extra={"blocked_ips": config['blocked_ips']})
    log_event(f"Blocked Ports: {config['blocked_ports']}", "INFO", extra={"blocked_ports": config['blocked_ports']})
    log_event(f"Blocked Protocols: {config['blocked_protocols']}", "INFO", extra={"blocked_protocols": config['blocked_protocols']})
    log_event(f"Rules: {config['rules']}", "INFO", extra={"rules": config['rules']})
    return config
    
def add_rule(rule):
  config = load_config()
  config["rules"].append(rule)
  save_config(config)
  log_event(f"Added rule: {rule}", "INFO", extra={"rule": rule})

def remove_rule(rule):
  config = load_config()
  if rule in config["rules"]:
      config["rules"].remove(rule)
      save_config(config)
      log_event(f"Removed rule: {rule}", "INFO", extra={"rule": rule})
  else:
      log_event(f"Rule not found: {rule}", "INFO", extra={"rule": rule})


# Yeni: Komut satırı arayüzü (CLI) fonksiyonu
def run_cli():
    """Komut satırı arayüzünü çalıştırır."""
    parser = argparse.ArgumentParser(description="PyWall Lite CLI")
    subparsers = parser.add_subparsers(title='commands', dest='command', help='Available commands')
    
    # Blok IP adresleri komutu
    block_ip_parser = subparsers.add_parser("block_ip", help="Block an IP address")
    block_ip_parser.add_argument("ip", type=str, help="IP address to block")
    
    unblock_ip_parser = subparsers.add_parser("unblock_ip", help="Unblock an IP address")
    unblock_ip_parser.add_argument("ip", type=str, help="IP address to unblock")

    # Blok Port komutu
    block_port_parser = subparsers.add_parser("block_port", help="Block a port")
    block_port_parser.add_argument("port", type=int, help="Port to block")
    
    unblock_port_parser = subparsers.add_parser("unblock_port", help="Unblock a port")
    unblock_port_parser.add_argument("port", type=int, help="Port to unblock")
    
    # Blok Protokol komutu
    block_protocol_parser = subparsers.add_parser("block_protocol", help="Block a protocol")
    block_protocol_parser.add_argument("protocol", type=str, help="Protocol to block (tcp, udp)")
    
    unblock_protocol_parser = subparsers.add_parser("unblock_protocol", help="Unblock a protocol")
    unblock_protocol_parser.add_argument("protocol", type=str, help="Protocol to unblock (tcp, udp)")
    
    # Blok kural komutu
    block_rule_parser = subparsers.add_parser("block_rule", help="Add a block rule")
    block_rule_parser.add_argument("--ip", type=str, help="IP address to match (regex)")
    block_rule_parser.add_argument("--port", type=int, help="Port to match")
    block_rule_parser.add_argument("--protocol", type=str, help="Protocol to match (tcp, udp)")
    
    unblock_rule_parser = subparsers.add_parser("unblock_rule", help="Remove a block rule")
    unblock_rule_parser.add_argument("--ip", type=str, help="IP address to match (regex)")
    unblock_rule_parser.add_argument("--port", type=int, help="Port to match")
    unblock_rule_parser.add_argument("--protocol", type=str, help="Protocol to match (tcp, udp)")

    # Listeleme Komutu
    list_parser = subparsers.add_parser("list", help="List blocked items")

    # Logları Göster Komutu
    logs_parser = subparsers.add_parser("logs", help="Show logs")
    
    args = parser.parse_args()
    
    if args.command == "block_ip":
        add_blocked_ip(args.ip)
    elif args.command == "unblock_ip":
        remove_blocked_ip(args.ip)
    elif args.command == "block_port":
        add_blocked_port(args.port)
    elif args.command == "unblock_port":
        remove_blocked_port(args.port)
    elif args.command == "block_protocol":
       add_blocked_protocol(args.protocol)
    elif args.command == "unblock_protocol":
       remove_blocked_protocol(args.protocol)
    elif args.command == "block_rule":
      rule = {}
      if args.ip:
          rule["ip"] = args.ip
      if args.port:
          rule["port"] = args.port
      if args.protocol:
          rule["protocol"] = args.protocol
      add_rule(rule)
    elif args.command == "unblock_rule":
         rule = {}
         if args.ip:
             rule["ip"] = args.ip
         if args.port:
              rule["port"] = args.port
         if args.protocol:
             rule["protocol"] = args.protocol
         remove_rule(rule)
    elif args.command == "list":
        list_blocked()
    elif args.command == "logs":
        show_logs()

def show_logs():
  log_file_path = LOG_FILE
  if os.path.exists(log_file_path):
      with open(log_file_path, 'r') as f:
          log_content = f.read()
      print(log_content)
  else:
    print("Log file not found.")


if __name__ == "__main__":
    
    import sys
    if len(sys.argv) > 1:
        run_cli()
    else:
        HOST = "0.0.0.0"
        PORT = 12345
    
        async def main():
            await start_server(HOST, PORT)

        # Firewall Server'ı Başlat
        import threading
        server_thread = threading.Thread(target=asyncio.run, args=(main(),))
        server_thread.daemon = True
        server_thread.start()
        
        # Web Arayüzünü Başlat
        from web_app import app
        app.run(debug=True, host='0.0.0.0', use_reloader=False)