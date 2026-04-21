# Network Attack Defence Simulator (NADS)

A Flask-based network security application designed to monitor, analyze, and detect suspicious network activity using packet sniffing and machine learning techniques. The system provides a real-time dashboard for visualizing network traffic and identifying potential threats.

---

## Overview

The Network Attack Defence Simulator (NADS) is built to demonstrate how network traffic can be inspected and analyzed to detect anomalies. It integrates packet capture with a machine learning pipeline to simulate intrusion detection in a controlled environment.

---

## Features

* Real-time packet sniffing using Scapy
* Machine learning-based anomaly detection
* Interactive dashboard for traffic monitoring
* Alert system for suspicious activities
* Persistent logging of alerts and system events
* Demo mode for safe simulation without real traffic

---

## Tech Stack

* Backend: Python, Flask
* Networking: Scapy
* Machine Learning: Scikit-learn, NumPy
* Frontend: HTML, CSS, JavaScript

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/Network_Attack_Defence_Simulator.git
cd Network_Attack_Defence_Simulator
```

---

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

Activate the environment:

* Windows:

```bash
venv\Scripts\activate
```

* Linux/macOS:

```bash
source venv/bin/activate
```

---

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

Note: Ensure that `scikit-learn`, `numpy`, and `scapy` are installed successfully, as they are required for machine learning and packet capture functionality.

---

## Usage

### 1. Configure Mode

Open `sniffer.py` and set:

```python
DEMO_MODE = True
```

* `True`: Runs the application in simulation mode
* `False`: Enables real-time traffic analysis

---

### 2. Run the Application

Packet sniffing requires elevated privileges.

* Windows (Run Command Prompt as Administrator):

```bash
python app.py
```

* Linux/macOS:

```bash
sudo $(which python) app.py
```

---

### 3. Access the Dashboard

If the browser does not open automatically, navigate to:

```
http://127.0.0.1:5050
```

---

## Project Structure

```text
NADS/
├── app.py              # Main Flask application and API routes
├── sniffer.py          # Packet sniffing and detection logic
├── requirements.txt    # Python dependencies
├── alerts.txt          # Alert logs
├── attack_logs.txt     # System event logs
├── static/             # Frontend assets (CSS, JS)
└── templates/          # HTML templates
```

---

## Important Notes

* Administrative/root privileges are required for packet sniffing
* Full functionality is more reliable on Linux systems
* Use demo mode if permissions or live traffic access are restricted

---

## Future Enhancements

* Add authentication and user management
* Improve machine learning model performance
* Containerize the application using Docker
* Deploy for real-time remote monitoring

---

## Author

GADHAM PRAKASH

---

## License

This project is intended for educational use. Add an appropriate license if you plan to distribute or reuse it.
