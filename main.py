from flask import Flask, render_template, jsonify, request, abort, redirect
from functools import wraps
from flask_wtf import FlaskForm
import time
import logging
from wtforms import Form, StringField, validators,SubmitField, TextAreaField
import email_validator
import re
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'waffles'

blocked_ips = {'146.249.223.167', '127.221.255.166', '92.60.219.99', '12.44.22.14', '50.161.69.129'}
inc_requests = []

request_counts = {}

logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def rate_limit(limit, window):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            current_time = int(time.time())
            
            if ip not in request_counts:
                request_counts[ip] = {'timestamp': current_time, 'count': 0}
            
            if current_time - request_counts[ip]['timestamp'] > window:
                request_counts[ip]['timestamp'] = current_time
                request_counts[ip]['count'] = 0
            
            request_counts[ip]['count'] += 1
            if request_counts[ip]['count'] > limit:
                blocked_ips.add(ip)
                logging.warning(f"Rate limit exceeded for IP: {ip}")
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

class IPForm(Form):
    ip = StringField('IP Address', validators=[validators.IPAddress(message='Invalid IP address')])

class MyForm(FlaskForm):
    name = StringField('Name', validators=[validators.InputRequired()])
    email = StringField('Email', validators=[validators.InputRequired(), validators.Email()])
    message = TextAreaField('Message', validators=[validators.InputRequired(), validators.Length(min=1, max=500)])
    submit_button = SubmitField('Submit')

@app.before_request
def log_request():
    if not (request.path.startswith("/static/") or request.path == "/control" ):
        ip = request.remote_addr
        req_info = {
            'method': request.method,
            'path': request.path,
            'remote_addr': request.remote_addr,
            'headers': dict(request.headers),
            'data': request.get_data().decode('utf-8'),
            'blocked': ip in blocked_ips 
        }
        inc_requests.append(req_info)
        logging.info(f"Incoming request: {req_info}")

@app.before_request
def before_request():
    ip = request.remote_addr
    if is_blocked(ip) and not request.path == "/control" and not request.path == "/static/index.css" and not request.path == "/block-ip" and not request.path == "/unblock-ip":
        logging.warning(f"Access denied: Blocked IP attempted access: {ip}")
        abort(403)

def is_blocked(ip):
    return ip in blocked_ips

#Web Pages

@app.route('/')
@rate_limit(limit=10, window=60)
def index():
    return render_template('main.html')

@app.route('/emailmee', methods=['GET', 'POST'])
@rate_limit(limit=10, window=60)
def email():
    form = MyForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        message = form.message.data
        
        ip = request.remote_addr

        if is_valid_message(message):
            data = {
                'name': name,
                'email': email,
                'message': message
            }
        
            response = requests.post('https://formsubmit.co/rdl4bs@gmail.com', data=data)
            
            if response.status_code == 200:
                return f'Email submitted successfully {name}!'
            else:
                return f'Failed to submit email. Please try again later.'
        else:
            blocked_ips.add(ip)
            abort(403) 
    return render_template('emailmee.html', form=form)

@app.route('/control')
def control():
    return render_template('index.html', blocked_ips=blocked_ips, inc_requests=inc_requests)

#Methods

@app.route('/block-ip', methods=['POST'])
def block_ip():
    form = IPForm(request.form)
    if form.validate():
        ip = form.ip.data
        blocked_ips.add(ip)
        logging.info(f"IP address {ip} added to Blocked IPs List")
        return jsonify({'message': f'IP address {ip} added to Blocked IPs List'}), 200
    else:
        logging.error("Invalid IP address provided in block request")
        return jsonify({'error': 'Invalid IP address'}), 400

@app.route('/unblock-ip', methods=['POST'])
def unblock_ip():
    form = IPForm(request.form)
    if form.validate():
        ip = form.ip.data
        blocked_ips.discard(ip)
        logging.info(f"IP address {ip} removed from Blocked IPs List")
        return jsonify({'message': f'IP address {ip} removed from Blocked IPs List'}), 200
    else:
        logging.error("Invalid IP address provided in unblock request")
        return jsonify({'error': 'Invalid IP address'}), 400
    
@app.route('/emailmee/submit-email', methods=['GET', 'POST'])
def submit_email():
    form = MyForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        message = form.message.data
        
        ip = request.remote_addr

        if is_valid_message(message) and is_valid_message(name) and is_valid_message(email):
            data = {
                'name': name,
                'email': email,
                'message': message
            }
        
            response = requests.post('https://formsubmit.co/rdl4bs@gmail.com', data=data)
            
            if response.status_code == 200:
                return f'Email submitted successfully {name}!'
            else:
                return f'Failed to submit email. Please try again later.'
        else:
            blocked_ips.add(ip)
            abort(403)

    else:
        return redirect('/emailmee')

def is_valid_message(message):
    profanity_list = [
        "shit", "fuck", "asshole", "retard", "cunt",
        "bitch", "bastard", "dick", "cock", "pussy",
        "motherfucker", "whore", "slut", "faggot",
        "ass", "twat", "damn", "crap", "hell",
        "goddamn", "son of a bitch", "fuckwit", "wanker",
        "bollocks", "arse", "bugger", "piss", "prick",
        "sucker", "freak", "idiot", "moron", "loser"
    ]
    for word in profanity_list:
        if re.search(r'\b{}\b'.format(re.escape(word)), message, re.IGNORECASE):
            return False
    
    attack_patterns = [
        r'<script>', r'javascript:', r'onmouseover=', r'onclick=',
        r'eval\(', r'alert\(', r'document\.cookie', r'<iframe',
        r'select\s+\*\s+from', r'insert into', r'delete from',
        r'update set', r'--', r'\s+or\s+', r'1=1', r'union\s+select',
        r'exec\s+', r'cmd=', r'etc/passwd', r'\.\./\.\./'
    ]

    for pattern in attack_patterns:
        if pattern in message.lower():
            return False
    
    max_length = 500 
    if len(message) > max_length: 
        return False
    
    return True

#<a href="javascript:alert('XSS')">Click me</a>
#<img src="image.jpg" onmouseover="alert('XSS')">
#'INSERT INTO users (username, password) VALUES ('admin', 'password')'
#'DELETE FROM users WHERE id = 1'
#'UPDATE users SET password = 'newpassword' WHERE username = 'admin''
#exec('ls -la')

if __name__ == '__main__':
    app.run(debug=True)

