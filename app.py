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
import google.generativeai as genai
import joblib
import pandas as pd
import numpy as np

# Set up logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()])
logger = logging.getLogger('snort-dashboard')

app = Flask(__name__, static_folder='static')
CORS(app)  # Enable CORS for all routes

# Configure Google Generative AI API
GOOGLE_API_KEY= "AIzaSyCeSOVKuf2Gv_VvqQkEWhYGDyg-5vUrtEk"  # Replace with your actual API key  # Replace with your actual API key
genai.configure(api_key=GOOGLE_API_KEY)

# Create models directory if it doesn't exist
os.makedirs('models', exist_ok=True)

# Load ML models if available
try:
    if os.path.exists('models/malicious_traffic_model.pkl'):
        malicious_traffic_model = joblib.load('models/malicious_traffic_model.pkl')
        logger.info("Malicious traffic model loaded successfully")
    else:
        malicious_traffic_model = None
        logger.warning("Malicious traffic model file not found")
        
    if os.path.exists('models/anomaly_detection_model.pkl'):
        anomaly_detection_model = joblib.load('models/anomaly_detection_model.pkl')
        logger.info("Anomaly detection model loaded successfully")
    else:
        anomaly_detection_model = None
        logger.warning("Anomaly detection model file not found")
except Exception as e:
    logger.error(f"Error loading ML models: {str(e)}", exc_info=True)
    malicious_traffic_model = None
    anomaly_detection_model = None

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
    'Ping of Death': 0,
    'Ping Flood': 0,
    'SSH Attack': 0,
    'Nmap Scan': 0,
    'SQL Injection': 0,
    'XSS Attack': 0,
    'Other': 0
}

# Chatbot system prompt
CHATBOT_SYSTEM_PROMPT = """
You are a Snort rule generation assistant. Generate valid, efficient Snort rules based on user descriptions.
Follow these guidelines:
1. Each rule should have correct syntax for the latest Snort version
2. Include header (action, protocol, IP addresses, ports) and rule options
3. Use appropriate Snort keywords and options
4. ALWAYS include the 'msg:' option with a descriptive message
5. ALWAYS include the 'sid:' option with a unique ID above 1000000
6. For complex scenarios, provide multiple rules if needed
7. Format your response as pure Snort rules without markdown code blocks

Example of a properly formatted rule:
alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; content:"union select"; nocase; sid:1000001; rev:1;)

Format your response as valid Snort rules only. Do not include explanations outside of comments.
"""

def get_gemini_model():
    """Get the appropriate Gemini model."""
    return "models/gemini-1.5-flash"

def generate_snort_rule(prompt):
    """
    Generate Snort rules using Gemini API based on user input
    """
    try:
        # Get the correct model name
        model_name = get_gemini_model()
        
        # Log the model being used
        logger.info(f"Using model: {model_name}")
        logger.info(f"Generating rule for prompt: {prompt}")
        
        # Initialize the model
        model = genai.GenerativeModel(model_name)
        
        # Create a comprehensive prompt for Gemini
        complete_prompt = f"{CHATBOT_SYSTEM_PROMPT}\n\nUser request: {prompt}\n\nGenerate appropriate Snort rule(s):"
        logger.info(f"Complete prompt (first 100 chars): {complete_prompt[:100]}...")
        
        # Generate content with safety settings
        generation_config = {
            "temperature": 0.2,
            "top_p": 0.8,
            "top_k": 40,
            "max_output_tokens": 1024,
        }
        
        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        ]
        
        logger.info("Sending request to Gemini API...")
        response = model.generate_content(
            complete_prompt,
            generation_config=generation_config,
            safety_settings=safety_settings
        )
        
        logger.info(f"Response received (first 100 chars): {response.text[:100]}...")
        return response.text
    except Exception as e:
        # Include detailed error information
        error_msg = f"Error generating Snort rule: {str(e)}"
        if hasattr(e, 'status_code'):
            error_msg += f" (Status code: {e.status_code})"
        logger.error(error_msg, exc_info=True)
        return error_msg

def validate_rule(rule_text):
    """
    Basic validation of Snort rule syntax
    """
    # Check for common syntax elements
    if not rule_text or len(rule_text) < 10:
        return False, "Rule is too short"
    
    # Check if this is a code block or has formatting from Gemini
    rule_text = rule_text.replace("```", "").strip()
    
    # Some rules might be in a comment or explanation
    # Extract the actual rule if possible
    lines = rule_text.split("\n")
    rule_lines = [line for line in lines if line.strip() and not line.strip().startswith("#")]
    
    if not rule_lines:
        return False, "No valid rule found"
    
    # Join multiple lines if needed
    rule_text = " ".join(rule_lines)
    
    # Basic format checks
    if "alert" not in rule_text and "log" not in rule_text and "drop" not in rule_text and "reject" not in rule_text and "pass" not in rule_text:
        return False, "Missing valid action (alert, log, drop, reject, pass)"
    
    if "->" not in rule_text:
        return False, "Missing direction operator (->)"
    
    if "(" not in rule_text or ")" not in rule_text:
        return False, "Missing rule options parentheses"
    
    return True, "Rule syntax looks valid"

def parse_alert_line(line):
    """Parse a line from Snort's alert output with more accurate pattern matching"""
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
        message = message_match.group(1).lower()
        
        # Classify based on message content
        line_lower = line.lower()
        
        # Protocol identification
        if "icmp" in line_lower:
            alert['protocol'] = 'ICMP'
            
            # More specific ICMP attack types
            if any(x in message for x in ["ping of death", "oversized", "large"]):
                alert['type'] = 'Ping of Death'
            elif any(x in message for x in ["ping flood", "flood", "destination unreachable flood"]):
                alert['type'] = 'Ping Flood'
            else:
                alert['type'] = 'ICMP'
                
        elif "tcp" in line_lower:
            alert['protocol'] = 'TCP'
            alert['type'] = 'TCP'
            
        elif "udp" in line_lower:
            alert['protocol'] = 'UDP'
            alert['type'] = 'UDP'
        
        # Attack type identification
        if "ssh" in message or "suspicious ssh" in message:
            alert['type'] = 'SSH Attack'
            
        elif any(x in message for x in ["scan", "sweep", "port scan", "nmap"]):
            alert['type'] = 'Nmap Scan'
            
        elif any(x in message for x in ["sql", "injection", "sql injection", "or 1=1"]):
            alert['type'] = 'SQL Injection'
            
        elif any(x in message for x in ["xss", "cross-site", "script", "<script>"]):
            alert['type'] = 'XSS Attack'
    
    # Extract IP addresses
    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?(\d+\.\d+\.\d+\.\d+)', line)
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
            attack_types = ['Ping of Death', 'Ping Flood', 'SSH Attack', 'Nmap Scan', 'SQL Injection', 'XSS Attack']
            if alert['type'] in attack_types:
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
            'Ping of Death': 0,
            'Ping Flood': 0,
            'SSH Attack': 0,
            'Nmap Scan': 0,
            'SQL Injection': 0,
            'XSS Attack': 0,
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

# Chatbot API endpoint for generating Snort rules
@app.route('/api/generate-rule', methods=['POST'])
def api_generate_rule():
    """API endpoint to generate a Snort rule"""
    try:
        data = request.json
        prompt = data.get('prompt', '')
        
        if not prompt:
            return jsonify({'status': 'error', 'message': 'No prompt provided'}), 400
            
        logger.info(f"Generating Snort rule for prompt: {prompt}")
        
        # Generate the rule
        rule = generate_snort_rule(prompt)
        
        # Validate the rule
        is_valid, validation_message = validate_rule(rule)
        
        return jsonify({
            'status': 'success',
            'rule': rule,
            'is_valid': is_valid,
            'validation_message': validation_message
        })
    except Exception as e:
        logger.error(f"Error generating rule: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': str(e)}), 500

# API endpoint for ML-based traffic analysis
@app.route('/api/analyze-traffic', methods=['POST'])
def analyze_traffic():
    """Analyze traffic data using ML models and generate Snort rules with Google AI"""
    try:
        # Get the request data
        data = request.get_json(force=True)
        traffic_data = data.get('traffic_data', [])
        
        # Validate input
        if not traffic_data or not isinstance(traffic_data, list):
            return jsonify({
                'status': 'error', 
                'message': 'Invalid or empty traffic data'
            }), 400
            
        logger.info(f"Analyzing traffic data, {len(traffic_data)} records received")
        
        # Convert to DataFrame with error handling
        try:
            df = pd.DataFrame(traffic_data)
        except Exception as df_error:
            logger.error(f"Error converting to DataFrame: {str(df_error)}")
            return jsonify({
                'status': 'error', 
                'message': f'Error processing data: {str(df_error)}'
            }), 400
        
        # Validate DataFrame
        if df.empty:
            return jsonify({
                'status': 'error', 
                'message': 'No valid data found in the uploaded file'
            }), 400
        
        # Log columns for debugging
        logger.info(f"DataFrame columns: {df.columns.tolist()}")
        
        # Prepare analysis results with default values
        results = {
            'malicious_traffic': [0] * len(df),
            'anomalies': [0] * len(df),
            'analysis_summary': 'Traffic analysis complete'
        }
        
        # Prepare prompt for rule generation
        prompt = "Generate Snort rules to detect and prevent network threats based on the following analysis:\n\n"
        
        # Analyze specific attack types
        if 'Type' in df.columns:
            attack_types = df['Type'].value_counts()
            
            prompt += "Detected Attack Types:\n"
            for attack_type, count in attack_types.items():
                prompt += f"- {attack_type}: {count} instances\n"
                
                # Mark potentially malicious traffic
                if attack_type in ['Nmap Scan', 'SQL Injection', 'XSS Attack']:
                    results['malicious_traffic'] = [1 if t == attack_type else 0 for t in df['Type']]
        
        # Add source and destination IP analysis
        if 'Source' in df.columns:
            unique_sources = df['Source'].value_counts()
            prompt += "\nSource IP addresses of concern:\n"
            for ip, count in unique_sources.head(5).items():
                prompt += f"- {ip}: {count} occurrences\n"
        
        prompt += "\nGenerate comprehensive Snort rules to block or alert on these threats."
        
        logger.info(f"Generated rule generation prompt: {prompt}")
        
        # Generate rules using Gemini
        try:
            # Use the appropriate Gemini model
            model_name = get_gemini_model()
            model = genai.GenerativeModel(model_name)
            
            # Configure generation parameters
            generation_config = {
                "temperature": 0.3,
                "top_p": 0.8,
                "top_k": 40,
                "max_output_tokens": 1024,
            }
            
            # Generate Snort rules
            response = model.generate_content(
                f"{CHATBOT_SYSTEM_PROMPT}\n\n{prompt}\n\nGenerate appropriate Snort rule(s):",
                generation_config=generation_config
            )
            
            # Extract and clean the rules
            suggested_rules = response.text.strip().split('\n\n')
            
            # Remove any code block formatting
            suggested_rules = [
                rule.replace('```', '').strip() 
                for rule in suggested_rules 
                if rule.strip()
            ]
            
            logger.info(f"Generated {len(suggested_rules)} Snort rules")
            
            return jsonify({
                'status': 'success',
                'results': results,
                'suggested_rules': suggested_rules
            })
            
        except Exception as ai_error:
            logger.error(f"Error generating rules with Google AI: {str(ai_error)}", exc_info=True)
            return jsonify({
                'status': 'error', 
                'message': f"AI rule generation failed: {str(ai_error)}"
            }), 500
        
    except Exception as e:
        logger.error(f"Error analyzing traffic: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error', 
            'message': f"Unexpected error: {str(e)}"
        }), 500# Endpoint to render chatbot page
@app.route('/rule-generator')
def rule_generator():
    return send_from_directory('static', 'rule-generator.html')

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
    
    # AI model status
    output += "<h2>AI Models Status</h2>"
    output += f"<p>Malicious Traffic Model: {'Loaded' if malicious_traffic_model else 'Not Loaded'}</p>"
    output += f"<p>Anomaly Detection Model: {'Loaded' if anomaly_detection_model else 'Not Loaded'}</p>"
    
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