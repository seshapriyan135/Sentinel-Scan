from flask import Flask, render_template, redirect, url_for

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/port_scanner')
def port_scanner():
    return redirect('http://127.0.0.1:5002')

@app.route('/packet_sniffer')
def packet_sniffer():
    return redirect('http://127.0.0.1:5001')

if __name__ == '__main__':
    app.run(debug=True)
