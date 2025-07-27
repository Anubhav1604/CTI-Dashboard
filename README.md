# CTI-Dashboard
This is Cyber Threat Intelligence Dashboard 

A Flask-based dashboard for running Nmap scans, visualizing threats, and generating PDF reports.

## Features
- Run Nmap scans via web interface  
- Real-time results with charts  
- PDF report generation  

## Quick Start
1. Install Python 3.10+ and Nmap.
2. Clone and run:
   ```bash
   git clone https://github.com/yourusername/cyber-threat-dashboard.git
   cd cyber-threat-dashboard
   pip install -r requirements.txt
   python app_fix_route.py

3. Access http://127.0.0.1:5000.


## Setup
1. Install [MongoDB](https://www.mongodb.com/try/download/community) and Nmap.
2. Configure MongoDB URI in `app_fix_route.py`:
   ```python
   app.config["MONGO_URI"] = "mongodb://localhost:27017/scan_db"
3. Packages u have to install more are : eventlet ,greenlet , pip, dns .
