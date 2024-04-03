#SentinelScan: Advanced Network Scanner and Packet Detection Suite

SentinelScan empowers you to monitor network activity, detect vulnerabilities, and analyze network traffic in real-time. Built with Python, Flask, and Scapy, this suite provides a user-friendly interface to strengthen your network defenses.

Key Features

Port Scanning:
Scans target IP addresses for open ports.
Asynchronous scanning provides quick and efficient results.
Identifies services running on open ports.
Detects vulnerabilities using a curated list of vulnerable ports.
Packet Sniffing:
Captures and analyzes network packets in real-time.
Examines packet headers and payloads.
Decrypts traffic where possible.
Web Interface:
User-friendly interface to initiate scans and packet analysis.
Real-time updates using Flask-SocketIO.
Getting Started

Installation:
Bash
pip install Flask Flask-SocketIO scapy
Use code with caution.
Running the Application:
Bash
python app.py 
Use code with caution.
Accessing the Interface: Open http://127.0.0.1:5001 in your web browser.
Usage

Port Scanning:

Enter a target IP address.
Click "Start Scan".
View scan results with port status, service information, and potential vulnerabilities.
Packet Sniffing:

Select an interface to monitor.
Click "Start Sniffing"
View captured packets with details, including source/destination IP, payload, and decrypted data (if applicable).
Contributing

We welcome contributions to SentinelScan!

Fork the repository.
Submit pull requests with well-documented changes.
Open issues for bug reports and feature requests.
Disclaimer

SentinelScan is intended for security professionals and network administrators. Use this tool responsibly and with respect for the privacy and security of network resources.
