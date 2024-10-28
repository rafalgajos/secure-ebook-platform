# Standard imports
import mimetypes
import uuid
import logging
import os
import hmac
import hashlib
import json
import magic  # For MIME type checking
import requests

# External imports
import apsw
import sqlite3
from flask import Flask, render_template, request, redirect, session, url_for, abort
from werkzeug.utils import secure_filename

# Flask app configuration
app = Flask(__name__)
app.config['SQLIN_PROTECTION_ENABLED'] = True
app.config['XSS_PROTECTION_ENABLED'] = True
app.config['CSRF_PROTECTION_ENABLED'] = True
app.config['SESSION_HIJACK_PROTECTION_ENABLED'] = True
app.config['FILE_UPLOAD_PROTECTION_ENABLED'] = True
app.secret_key = 'super_secret_key'

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Database and file upload configurations
DATABASE = 'reviews.db'
MAX_FILE_SIZE = 5 * 1024 * 1024  # Maximum file size (e.g., 5 MB)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'pdf'}
ALLOWED_MIME_TYPES = {'application/pdf'}

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Load API key from the external file for VirusTotal integration
def load_api_key_from_txt():
    """Load the VirusTotal API key from a text file."""
    try:
        with open('virus_total_api.txt', 'r') as f:
            api_key = f.read().strip()  # Read and strip any trailing whitespace
            return api_key
    except FileNotFoundError:
        raise FileNotFoundError("The virus_total_api.txt file was not found.")
    except Exception as e:
        raise ValueError(f"Error while reading the API key: {e}")

# Load the VirusTotal API key
VIRUSTOTAL_API_KEY = load_api_key_from_txt()

if not VIRUSTOTAL_API_KEY:
    raise ValueError("Missing VirusTotal API key. Ensure virus_total_api.txt is properly configured.")


# VirusTotal file scanning functions
def scan_file_with_virustotal(file_path):
    """Scan the file using VirusTotal API and return the scan status."""
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': VIRUSTOTAL_API_KEY}
    files = {'file': (file_path, open(file_path, 'rb'))}

    try:
        with open(file_path, 'rb') as f:
            response = requests.post(url, files={'file': (file_path, f)}, params=params)

        if response.status_code == 200:
            json_response = response.json()
            scan_id = json_response.get('scan_id')
            if scan_id:
                return scan_id
            else:
                app.logger.error("Scan ID not returned in the response.")
                return None
        else:
            app.logger.error(f"Failed to initiate scan: {response.status_code}")
            return None
    except Exception as e:
        app.logger.error(f"Exception during VirusTotal scan initiation: {e}")
        return None


def check_virustotal_scan(scan_id):
    """Check VirusTotal scan report by scan_id. Returns False if the file is infected."""
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': scan_id}

    try:
        response = requests.get(url, params=params)

        if response.status_code == 200:
            json_response = response.json()

            # Check that the response contains the ‘positives’ and ‘total’ keys
            if 'positives' not in json_response or 'total' not in json_response:
                app.logger.error("VirusTotal did not return 'positives' or 'total' values in the response.")
                return False, 0, 0  # Treat file as infected if response is incomplete

            positives = json_response.get('positives')
            total = json_response.get('total')

            if positives > 0:
                app.logger.warning(f"VirusTotal found {positives} positives out of {total} scans.")
                return False, positives, total  # Infected file
            else:
                app.logger.info(f"VirusTotal scan is clean ({positives}/{total}).")
                return True, positives, total  # Clean file
        else:
            app.logger.error(f"Failed to retrieve VirusTotal scan report: {response.status_code}")
            return False, 0, 0  # Treat file as infected, if cannot be checked
    except Exception as e:
        app.logger.error(f"Exception during VirusTotal report check: {e}")
        return False, 0, 0


# File type and size validation functions
def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Create database table for reviews
def create_reviews_table():
    """Create 'reviews' table if it doesn't exist."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS reviews (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL,
                            email TEXT NOT NULL,
                            content TEXT NOT NULL,
                            user_id TEXT NOT NULL
                        )''')
        conn.commit()
        app.logger.debug("Table 'reviews' created or already exists.")
    except sqlite3.Error as e:
        app.logger.error(f"Error creating table: {e}")
    finally:
        if conn:
            conn.close()

# Call the function to create the table when the app starts
create_reviews_table()

# CSRF token generation and validation
def generate_csrf_token():
    """Generate a CSRF token for the session if not already present."""
    if 'csrf_token' not in session:
        session['csrf_token'] = hmac.new(app.secret_key.encode(), session.get('user_id', '').encode(),
                                         hashlib.sha256).hexdigest()
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate the provided CSRF token."""
    if not app.config['CSRF_PROTECTION_ENABLED']:
        return True
    return hmac.compare_digest(session.get('csrf_token', ''), token)

# Database connection using APSW
def get_db_connection():
    """Get a database connection."""
    conn = apsw.Connection(DATABASE)
    return conn

# XSS protection function
def escape_html(text):
    """Escape HTML characters for XSS protection."""
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&#39;",
        ">": "&gt;",
        "<": "&lt;",
    }
    return "".join(html_escape_table.get(c, c) for c in text)

# Fetch the last review from the database
def get_last_review():
    """Retrieve the latest review from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        sql = "SELECT name, email, content, user_id FROM reviews ORDER BY id DESC LIMIT 1"
        cursor.execute(sql)
        row = cursor.fetchone()
    except apsw.SQLError as e:
        app.logger.error(f"Database error: {e}")
        row = None
    finally:
        cursor.close()
        conn.close()

    if row:
        name, email, content, user_id = row
        if app.config['XSS_PROTECTION_ENABLED']:
            name = escape_html(name)
            email = escape_html(email)
            content = escape_html(content)
            user_id = escape_html(user_id)
        return {'name': name, 'email': email, 'content': content, 'user_id': user_id}
    else:
        return None

# Flask app request handling and session protection
@app.before_request
def generate_session_id():
    """Generate a unique session ID if one does not exist and protect session hijacking."""
    session.permanent = True

    if 'user_id' not in session:
        session['user_id'] = str(uuid.uuid4())

    if 'csrf_token' not in session:
        session['csrf_token'] = generate_csrf_token()

    if app.config['SESSION_HIJACK_PROTECTION_ENABLED']:
        session_ip = session.get('session_ip')
        session_user_agent = session.get('session_user_agent')
        current_ip = request.remote_addr
        current_user_agent = request.headers.get('User-Agent')

        if not session_ip or not session_user_agent:
            session['session_ip'] = current_ip
            session['session_user_agent'] = current_user_agent
        elif session_ip != current_ip or session_user_agent != current_user_agent:
            session.clear()
            return redirect(url_for('hello'))

# Flask routes
@app.route('/')
def hello():
    """Redirect to the index page with session ID."""
    return redirect(url_for('index', session_id=session.get('user_id')))

@app.route('/<session_id>')
def index(session_id):
    """Render the main index page with protection flags and last review details."""
    thank_you_message = session.pop('thank_you_message', None)
    last_review = session.pop('last_review', None) or get_last_review()
    upload_message = session.pop('upload_message', None)

    if app.config['SESSION_HIJACK_PROTECTION_ENABLED']:
        if session_id != session.get('user_id'):
            app.logger.debug(f"Forbidden: session_id mismatch (URL: {session_id}, session: {session.get('user_id')})")
            abort(403)

        session_ip = session.get('session_ip')
        session_user_agent = session.get('session_user_agent')
        current_ip = request.remote_addr
        current_user_agent = request.headers.get('User-Agent')

        if session_ip != current_ip or session_user_agent != current_user_agent:
            session.clear()
            app.logger.debug("Forbidden: IP or User-Agent mismatch")
            abort(403)

    return render_template('index.html',
                           sqlin_protection_enabled=app.config['SQLIN_PROTECTION_ENABLED'],
                           xss_protection_enabled=app.config['XSS_PROTECTION_ENABLED'],
                           csrf_protection_enabled=app.config['CSRF_PROTECTION_ENABLED'],
                           session_hijack_protection_enabled=app.config['SESSION_HIJACK_PROTECTION_ENABLED'],
                           file_upload_protection_enabled=app.config['FILE_UPLOAD_PROTECTION_ENABLED'],
                           session_id=session_id,
                           thank_you_message=thank_you_message,
                           last_review=last_review,
                           upload_message=upload_message)

# Toggle protection routes (SQL Injection, XSS, CSRF, session hijack, file upload)
@app.route('/toggle-sqlin-protection', methods=['POST'])
def toggle_sqlin_protection():
    """Toggle SQL Injection protection."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    app.config['SQLIN_PROTECTION_ENABLED'] = not app.config['SQLIN_PROTECTION_ENABLED']
    return redirect('/')

@app.route('/toggle-xss-protection', methods=['POST'])
def toggle_xss_protection():
    """Toggle XSS protection."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    app.config['XSS_PROTECTION_ENABLED'] = not app.config['XSS_PROTECTION_ENABLED']
    return redirect('/')

@app.route('/toggle-csrf-protection', methods=['POST'])
def toggle_csrf_protection():
    """Toggle CSRF protection."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    app.config['CSRF_PROTECTION_ENABLED'] = not app.config['CSRF_PROTECTION_ENABLED']
    return redirect('/')

@app.route('/toggle-session-hijack-protection', methods=['POST'])
def toggle_session_hijack_protection():
    """Toggle session hijacking protection."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    app.config['SESSION_HIJACK_PROTECTION_ENABLED'] = not app.config['SESSION_HIJACK_PROTECTION_ENABLED']
    return redirect('/')

@app.route('/toggle-file-upload-protection', methods=['POST'])
def toggle_file_upload_protection():
    """Toggle file upload protection."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    app.config['FILE_UPLOAD_PROTECTION_ENABLED'] = not app.config['FILE_UPLOAD_PROTECTION_ENABLED']
    return redirect('/')

# Submit review route
@app.route('/submit-review/<session_id>', methods=['POST'])
def submit_review(session_id):
    """Handle the submission of a review."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)

    app.logger.debug(f"Submit review: URL session_id={session_id}, session user_id={session.get('user_id')}")

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    content = request.form.get('message', '').strip()
    user_id = session_id  # Use session_id as user_id

    if app.config['XSS_PROTECTION_ENABLED']:
        name = escape_html(name)
        email = escape_html(email)
        content = escape_html(content)
        user_id = escape_html(user_id)

    # Ensure all required fields are present
    if not name or not email or not content or not user_id:
        app.logger.error("One or more review details are missing.")
        abort(400, description="Bad Request: One or more review details are missing.")

    conn = get_db_connection()
    cursor = conn.cursor()
    sql = "INSERT INTO reviews (name, email, content, user_id) VALUES (?, ?, ?, ?)"

    try:
        malicious_result = None
        if app.config['SQLIN_PROTECTION_ENABLED']:
            cursor.execute(sql, (name, email, content, user_id))
        else:
            if "');" in name:
                base_name, sql_injection = name.split("');", 1)
                cursor.execute("INSERT INTO reviews (name, email, content, user_id) VALUES (?, ?, ?, ?)",
                               (base_name, email, content, user_id))
                malicious_sql = sql_injection.strip().replace('--', '')
                app.logger.debug(f"Executing malicious SQL: {malicious_sql}")

                if malicious_sql.strip().upper().startswith("SELECT"):
                    cursor.execute(malicious_sql)
                    malicious_result = cursor.fetchall()
                else:
                    cursor.execute(malicious_sql)
            else:
                cursor.execute(sql, (name, email, content, user_id))
    except apsw.SQLError as e:
        if "no such table: reviews" in str(e):
            app.logger.warning("Table 'reviews' does not exist, creating new table.")
            create_reviews_table()
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(sql, (name, email, content, user_id))
        else:
            app.logger.error(f"Error executing SQL: {e}")
            raise
    finally:
        cursor.close()
        conn.close()

    # Prepare the thank-you message
    if malicious_result:
        result_message = "<br>".join([", ".join([str(cell) for cell in row]) for row in malicious_result])
        thank_you_message = f"Thank you for adding your comment, {name}!<br>{result_message}"
    else:
        thank_you_message = f"Thank you for adding your comment, {name}!"

    # Save the last review
    last_review = {'name': name, 'email': email, 'content': content, 'user_id': user_id}
    session['thank_you_message'] = thank_you_message
    session['last_review'] = last_review
    return redirect(url_for('index', session_id=session_id))

# File upload route
@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload with VirusTotal scan if enabled."""
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)

    if 'ebook-file' not in request.files:
        session['upload_message'] = "No file part"
        return redirect(url_for('index', session_id=session.get('user_id')))

    file = request.files['ebook-file']
    if file.filename == '':
        session['upload_message'] = "No selected file"
        return redirect(url_for('index', session_id=session.get('user_id')))

    if file:
        if app.config['FILE_UPLOAD_PROTECTION_ENABLED']:
            mime = magic.Magic(mime=True)
            mime_type = mime.from_buffer(file.read(1024))
            file.seek(0)
            if mime_type not in ALLOWED_MIME_TYPES:
                session['upload_message'] = f"Invalid file type: {mime_type}"
                return redirect(url_for('index', session_id=session.get('user_id')))

            file.seek(0, os.SEEK_END)
            file_length = file.tell()
            file.seek(0)
            if file_length > MAX_FILE_SIZE:
                session['upload_message'] = "File is too large"
                return redirect(url_for('index', session_id=session.get('user_id')))

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(file_path)

        if app.config['FILE_UPLOAD_PROTECTION_ENABLED']:
            scan_id = scan_file_with_virustotal(file_path)
            if scan_id:
                is_clean, positives, total = check_virustotal_scan(scan_id)
                if not is_clean:
                    os.remove(file_path)
                    session['upload_message'] = (
                        f"File {file.filename} contains a virus and has been rejected. "
                        f"VirusTotal detected {positives} threats out of {total} scans."
                    )
                    return redirect(url_for('index', session_id=session.get('user_id')))
                else:
                    session['upload_message'] = (
                        f"File {file.filename} uploaded successfully and is clean. "
                        f"VirusTotal scan: {positives} positives out of {total} scans."
                    )
            else:
                session['upload_message'] = f"File {file.filename} uploaded but VirusTotal scan failed."
        else:
            session['upload_message'] = f"File {file.filename} uploaded successfully without VirusTotal scan."

        return redirect(url_for('index', session_id=session.get('user_id')))

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
