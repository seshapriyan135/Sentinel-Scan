from flask import Flask, render_template
from flask_socketio import SocketIO, emit
import socket
import sys
import base64

app = Flask(__name__)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")


obfuscated_ports = 'MjIsIDMyLCAzMzIsIDU1LCAxNDAsIDMxLCAtMzI3LCAyMCwgMjEsIDIzLCAxNDMzLCAxNDM0LCAzMzA2'

def decode_ports(obfuscated_ports):
    decoded = base64.b64decode(obfuscated_ports).decode('utf-8')
    return list(map(int, decoded.split(',')))


vulnerable_ports = decode_ports(obfuscated_ports)

@app.route('/')
def index():
    return render_template('index.html')

def get_service_and_version(port):
    try:
        service_name = socket.getservbyport(port)
        return service_name
    except (socket.error, OSError):
        return f"No service information available for port {port}"

def scan_ports(target_ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.1)  # Set a timeout for the connection attempt
    try:
        result = sock.connect_ex((target_ip, port))
        service_name = get_service_and_version(port)
        is_vulnerable = port in vulnerable_ports
        vulnerability_label = " (Potentially Vulnerable)" if is_vulnerable else ""
        if result == 0:
            status = "open"
        else:
            status = "close" 
            socketio.emit('port_scan_result', {'port': port, 'status': status, 'service': service_name, 'vulnerable': is_vulnerable})
            return 
        socketio.emit('port_scan_result', {'port': port, 'status': status, 'service': service_name, 'vulnerable': is_vulnerable})

    except (socket.gaierror, socket.error, OSError):
        pass 

    finally:
        sock.close()

@socketio.on('scan_ports')
def handle_scan_ports(data):
    target_ip = data['ipAddress']
    try:
        for port in range(data['startPort'], data['endPort'] + 1):
            socketio.start_background_task(scan_ports, target_ip, port)

    except KeyboardInterrupt:
        print("\nExiting Program !!!!")
        sys.exit()
    except socket.gaierror:
        print("\nHostname Could Not Be Resolved !!!!")
        sys.exit()
    except socket.error as e:
        print(f"\nError: {e}")
        sys.exit()

if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=5002, debug=True)