from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import sniff, IP, Raw
import time
import asyncio
import logging

app = Flask(__name__)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

running_flag = False
sniff_thread = None
security_flag=False
security_status="encrypted"

def decrypt_payload(hex_payload):
    try:
        
        ascii_payload = bytes.fromhex(hex_payload).decode('utf-8')
        
        if ascii_payload.isprintable():
            security_flag=True
            return ascii_payload
        else:
            
            security_flag=False
            return ascii_payload
    except UnicodeDecodeError:
        try:
          
            ascii_payload = bytes.fromhex(hex_payload).decode('latin-1')

            
            if ascii_payload.isprintable():
                security_flag=True
                return ascii_payload
            else:
               
                security_flag=False
                return hex_payload
        except Exception as e:
           
            return hex_payload

@socketio.on('connect')
def handle_connect():
    print('Client connected')

def packet_callback(packet):
    global running_flag

    if not security_flag:
        security_status="decrypted"
    else:
        security_status="encrypted"
       
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        payload_data = None

        if Raw in packet:
            hex_payload = packet[Raw].load.hex()
            payload_data = decrypt_payload(hex_payload)

        # print("Src IP:", src_ip)
        # print("Dst IP:", dst_ip)
        # print("Payload Data:", payload_data)

        
        socketio.emit('packet', {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'payload_data': payload_data,
            'packet_info': str(packet.summary()),
            'security_status':security_status
        })

async def sniff_packets_async(ip_address_to_sniff):
    global running_flag
    print("sniff_packets_async()")

    while running_flag:
        
        await asyncio.to_thread(sniff, filter="host "+ip_address_to_sniff, prn=packet_callback, store=0, timeout=1)
        await asyncio.sleep(0.1)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('execute_code')
def execute_code(data):
    global running_flag, sniff_thread

    if not running_flag:
        
        running_flag = True
        ip_address_to_sniff = data.get('ipAddress')
        print("execute_code()", running_flag,ip_address_to_sniff)

        
        sniff_thread = asyncio.run(sniff_packets_async(ip_address_to_sniff))

        print("Executing Python code")
    else:
        print("Thread already running")

@socketio.on('stop_code')
def stop_code():
    global running_flag, sniff_thread

    if running_flag:
       
        running_flag = False
        print("Stop Python code")
    else:
        print("Thread not running")

if __name__ == '__main__':
    
    
    socketio.run(app, host='127.0.0.1', port=5001, debug=True)
