from flask import Flask, render_template, jsonify, send_from_directory, request
import subprocess
import threading
import re
import os
import json
import time
import datetime
from flask_cors import CORS
import signal
import psutil
import tempfile
from fpdf import FPDF
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()])
logger = logging.getLogger('snort-dashboard')

app = Flask(__name__, static_folder='static')
CORS(app)  # Enable CORS for all routes

# Serve static files
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

# Global variables to store Snort state
snort_process = None
alert_buffer = []
is_monitoring = False
start_time = None
packet_count = 0
alert_count = 0
attack_count = 0
source_ips = {}
alert_types = {
    'ICMP': 0,
    'TCP': 0,
    'UDP': 0, 
    'Attack': 0,
    'Other': 0
}

def parse_alert_line(line):
    """Parse a line from Snort's alert output"""
    # This is a simplified parser and would need to be adapted to your actual Snort output format
    alert = {
        'timestamp': '',
        'type': 'Other',
        'message': '',
        'source': '',
        'destination': '',
        'protocol': '',
        'priority': 0
    }
    
    # Extract timestamp
    timestamp_match = re.search(r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)', line)
    if timestamp_match:
        alert['timestamp'] = timestamp_match.group(1)
    
    # Extract alert message
    message_match = re.search(r'\[\*\*\] \[.*\] (.*) \[\*\*\]', line)
    if message_match:
        alert['message'] = message_match.group(1)
    
    # Extract protocol and classify type
    if 'ICMP' in line:
        alert['protocol'] = 'ICMP'
        alert['type'] = 'ICMP'
    elif 'TCP' in line:
        alert['protocol'] = 'TCP'
        alert['type'] = 'TCP'
    elif 'UDP' in line:
        alert['protocol'] = 'UDP'
        alert['type'] = 'UDP'
    
    # Check if it's an attack alert
    attack_keywords = ['attack', 'exploit', 'scan', 'injection', 'overflow', 'xss', 'breach', 
                      'brute force', 'malware', 'backdoor', 'trojan', 'ransomware', 'shellcode']
    
    if any(keyword in line.lower() for keyword in attack_keywords):
        alert['type'] = 'Attack'
    
    # Extract IP addresses (simplified - would need improvement for a real implementation)
    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+) -> (\d+\.\d+\.\d+\.\d+)', line)
    if ip_match:
        alert['source'] = ip_match.group(1)
        alert['destination'] = ip_match.group(2)
    
    # Extract priority if available
    priority_match = re.search(r'\[Priority: (\d+)\]', line)
    if priority_match:
        alert['priority'] = int(priority_match.group(1))
    
    return alert

def monitor_snort_output():
    """Read and process Snort's output in real-time"""
    global alert_buffer, packet_count, alert_count, attack_count, source_ips, alert_types
    
    if snort_process is None:
        logger.error("Snort process is None")
        return
    
    logger.info(f"Monitoring Snort output on PID {snort_process.pid}")
    
    for line in iter(snort_process.stdout.readline, b''):
        if not is_monitoring:
            logger.info("Monitoring stopped")
            break
            
        line_str = line.decode('utf-8', errors='ignore').strip()
        logger.debug(f"Snort output: {line_str}")
        
        # Increment packet count (this is an approximation, real count would come from Snort stats)
        if "Commencing packet processing" in line_str:
            logger.info("Snort started packet processing")
            continue
            
        if "[**]" in line_str:  # This is an alert line
            logger.info(f"Alert detected: {line_str}")
            packet_count += 1
            alert_count += 1
            
            # Parse the alert
            alert = parse_alert_line(line_str)
            logger.debug(f"Parsed alert: {alert}")
            
            # Update alert counts
            if alert['type'] in alert_types:
                alert_types[alert['type']] += 1
            else:
                alert_types['Other'] += 1
                
            # Track attack count
            if alert['type'] == 'Attack':
                attack_count += 1
                
            # Track source IPs
            if alert['source']:
                if alert['source'] in source_ips:
                    source_ips[alert['source']] += 1
                else:
                    source_ips[alert['source']] = 1
            
            # Add to alert buffer (limit size to prevent memory issues)
            alert_buffer.append(alert)
            if len(alert_buffer) > 1000:
                alert_buffer.pop(0)
        
        # Also check for ICMP packets that might not trigger alerts
        elif "ICMP" in line_str:
            logger.info(f"ICMP packet detected: {line_str}")

# API Routes
@app.route('/api/status', methods=['GET'])
def get_status():
    """Get the current status of Snort monitoring"""
    global is_monitoring, start_time, alert_count, attack_count, packet_count
    
    uptime = 0
    if start_time:
        uptime = int(time.time() - start_time)
    
    return jsonify({
        'status': 'running' if is_monitoring else 'stopped',
        'uptime': uptime,
        'alerts': alert_count,
        'attacks': attack_count,
        'packets': packet_count
    })

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get the latest alerts"""
    # Get query parameters
    limit = request.args.get('limit', default=100, type=int)
    
    # Return the most recent alerts
    return jsonify(alert_buffer[-limit:])

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get alert statistics"""
    return jsonify({
        'alert_types': alert_types,
        'source_ips': source_ips
    })

@app.route('/api/start', methods=['POST'])
def start_monitoring():
    """Start Snort monitoring"""
    global snort_process, is_monitoring, start_time, alert_buffer
    global packet_count, alert_count, attack_count, source_ips, alert_types
    
    if is_monitoring:
        return jsonify({'status': 'already_running'})
    
    try:
        # Reset counters
        alert_buffer = []
        packet_count = 0
        alert_count = 0
        attack_count = 0
        source_ips = {}
        alert_types = {
            'ICMP': 0,
            'TCP': 0,
            'UDP': 0,
            'Attack': 0,
            'Other': 0
        }
        
        # Get interface from request
        data = request.json
        interface = data.get('interface', 'enp0s3')  # Default to enp0s3 if not specified
        logger.info(f"Starting Snort on interface: {interface}")
        
        # Start Snort process with the correct path
        cmd = ['sudo', '/usr/sbin/snort', '-A', 'console', '-v', '-q', '-i', interface, '-c', '/etc/snort/snort.conf']
        logger.info(f"Running command: {' '.join(cmd)}")
        snort_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        logger.info(f"Snort process started with PID: {snort_process.pid}")
        
        # Start monitoring thread
        is_monitoring = True
        start_time = time.time()
        monitor_thread = threading.Thread(target=monitor_snort_output)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        return jsonify({'status': 'started', 'pid': snort_process.pid})
    except Exception as e:
        logger.error(f"Error starting Snort: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    """Stop Snort monitoring"""
    global snort_process, is_monitoring
    
    if not is_monitoring:
        return jsonify({'status': 'not_running'})
    
    try:
        # Set flag to stop monitoring thread
        is_monitoring = False
        logger.info("Stopping Snort monitoring")
        
        # Terminate Snort process
        if snort_process:
            # Try graceful termination first
            logger.info(f"Terminating Snort process {snort_process.pid}")
            snort_process.terminate()
            try:
                snort_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Force kill if it doesn't terminate
                logger.warning(f"Snort process didn't terminate gracefully, killing it")
                snort_process.kill()
            
            # Make sure child processes are also terminated
            try:
                parent = psutil.Process(snort_process.pid)
                for child in parent.children(recursive=True):
                    logger.info(f"Terminating child process {child.pid}")
                    child.terminate()
            except:
                pass
            
            snort_process = None
        
        return jsonify({'status': 'stopped'})
    except Exception as e:
        logger.error(f"Error stopping Snort: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """Get available network interfaces"""
    interfaces = []
    try:
        # Get all network interfaces
        net_if = psutil.net_if_addrs()
        for interface in net_if:
            # Skip loopback interfaces
            if not interface.startswith('lo'):
                interfaces.append(interface)
        logger.info(f"Found interfaces: {interfaces}")
    except Exception as e:
        logger.error(f"Error getting interfaces: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
    return jsonify({'interfaces': interfaces})

@app.route('/debug')
def debug_view():
    """Debug view to help troubleshoot issues"""
    global alert_buffer, snort_process, is_monitoring, alert_count, packet_count
    
    output = "<h1>Snort Dashboard Debug Information</h1>"
    
    # System information
    output += "<h2>System Status</h2>"
    output += f"<p>Is monitoring: {is_monitoring}</p>"
    output += f"<p>Snort process running: {snort_process is not None}</p>"
    if snort_process:
        output += f"<p>Snort PID: {snort_process.pid}</p>"
        try:
            output += f"<p>Snort running: {psutil.Process(snort_process.pid).is_running()}</p>"
        except:
            output += "<p>Snort process not found by psutil</p>"
    output += f"<p>Alert count: {alert_count}</p>"
    output += f"<p>Packet count: {packet_count}</p>"
    output += f"<p>Alert buffer size: {len(alert_buffer)}</p>"
    
    # Alert types
    output += "<h2>Alert Types</h2>"
    output += "<ul>"
    for alert_type, count in alert_types.items():
        output += f"<li>{alert_type}: {count}</li>"
    output += "</ul>"
    
    # Recent alerts
    output += "<h2>Recent Alerts</h2>"
    if not alert_buffer:
        output += "<p>No alerts detected yet</p>"
    else:
        output += "<pre>"
        for alert in alert_buffer[-20:]:
            output += f"{alert['timestamp']} - {alert['type']} - {alert['message']} - {alert['source']} -> {alert['destination']}\n"
        output += "</pre>"
    
    # Test ICMP rule
    output += "<h2>Local Rules Check</h2>"
    try:
        with open('/etc/snort/rules/local.rules', 'r') as f:
            rules = f.read()
        output += "<pre>" + rules + "</pre>"
    except Exception as e:
        output += f"<p>Error reading rules: {str(e)}</p>"
    
    return output

@app.route('/api/report', methods=['GET'])
def generate_report():
    """Generate a PDF report of Snort alerts"""
    global alert_buffer, start_time, alert_count, attack_count, packet_count, alert_types, source_ips
    
    try:
        # Create a PDF report with error handling
        pdf = FPDF()
        pdf.add_page()
        
        # Add title
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Snort IDS Activity Report', 0, 1, 'C')
        
        # Add timestamp
        pdf.set_font('Arial', '', 10)
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        pdf.cell(0, 10, f'Generated on {current_time}', 0, 1, 'C')
        
        # Add summary section
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Summary', 0, 1, 'L')
        
        pdf.set_font('Arial', '', 10)
        uptime = "N/A"
        if start_time:
            uptime_seconds = int(time.time() - start_time)
            uptime = f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m {uptime_seconds % 60}s"
            
        pdf.cell(0, 6, f'Total Alerts: {alert_count}', 0, 1)
        pdf.cell(0, 6, f'Attack Alerts: {attack_count}', 0, 1)
        pdf.cell(0, 6, f'Packets Analyzed: {packet_count}', 0, 1)
        pdf.cell(0, 6, f'Monitoring Duration: {uptime}', 0, 1)
        
        # Add alert type distribution
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Alert Distribution', 0, 1, 'L')
        
        # Create a table for alert types
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(60, 7, 'Alert Type', 1)
        pdf.cell(30, 7, 'Count', 1)
        pdf.cell(30, 7, 'Percentage', 1)
        pdf.ln()
        
        pdf.set_font('Arial', '', 10)
        for alert_type, count in alert_types.items():
            percentage = 0
            if alert_count > 0:
                percentage = round((count / alert_count) * 100)
                
            pdf.cell(60, 6, alert_type, 1)
            pdf.cell(30, 6, str(count), 1)
            pdf.cell(30, 6, f'{percentage}%', 1)
            pdf.ln()
        
        # Add top source IPs
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Top Source IPs', 0, 1, 'L')
        
        # Create a table for top source IPs
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(60, 7, 'IP Address', 1)
        pdf.cell(30, 7, 'Alert Count', 1)
        pdf.cell(30, 7, 'Percentage', 1)
        pdf.ln()
        
        pdf.set_font('Arial', '', 10)
        top_ips = sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        for ip, count in top_ips:
            percentage = 0
            if alert_count > 0:
                percentage = round((count / alert_count) * 100)
                
            pdf.cell(60, 6, ip, 1)
            pdf.cell(30, 6, str(count), 1)
            pdf.cell(30, 6, f'{percentage}%', 1)
            pdf.ln()
        
        # Add recent alerts
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, 'Recent Alerts', 0, 1, 'L')
        
        # Create a table for recent alerts
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(30, 7, 'Time', 1)
        pdf.cell(20, 7, 'Type', 1)
        pdf.cell(60, 7, 'Message', 1)
        pdf.cell(80, 7, 'Source -> Destination', 1)
        pdf.ln()
        
        pdf.set_font('Arial', '', 8)
        recent_alerts = alert_buffer[-20:]  # Get most recent 20 alerts
        for alert in recent_alerts:
            # Truncate message if too long
            message = alert['message'] or "N/A"
            if len(message) > 30:
                message = message[:27] + '...'
                
            pdf.cell(30, 6, alert['timestamp'] or "N/A", 1)
            pdf.cell(20, 6, alert['type'], 1)
            pdf.cell(60, 6, message, 1)
            pdf.cell(80, 6, f"{alert['source'] or 'unknown'} -> {alert['destination'] or 'unknown'}", 1)
            pdf.ln()
        
        # Save to a temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        pdf_path = temp_file.name
        try:
            pdf.output(pdf_path)
            
            # Log success
            logger.info(f"PDF report generated successfully at {pdf_path}")
            
            # Return the file
            response = send_from_directory(
                os.path.dirname(pdf_path),
                os.path.basename(pdf_path),
                as_attachment=True
            )
            response.headers["Content-Disposition"] = "attachment; filename=snort_report.pdf"
            return response
            
        except Exception as pdf_error:
            logger.error(f"Error generating PDF output: {str(pdf_error)}", exc_info=True)
            return jsonify({'status': 'error', 'message': f"PDF generation error: {str(pdf_error)}"}), 500
            
    except Exception as e:
        logger.error(f"Error in report generation: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)