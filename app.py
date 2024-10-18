# Standard imports
import mimetypes
import uuid
import logging
import os
import hmac
import hashlib
import json
import magic  # Do sprawdzania MIME typu plików

# External imports
import apsw
import sqlite3
from flask import Flask, render_template, request, redirect, session, url_for, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SQLIN_PROTECTION_ENABLED'] = True
app.config['XSS_PROTECTION_ENABLED'] = True
app.config['CSRF_PROTECTION_ENABLED'] = True
app.config['SESSION_HIJACK_PROTECTION_ENABLED'] = True
app.config['FILE_UPLOAD_PROTECTION_ENABLED'] = True
app.secret_key = 'super_secret_key'

logging.basicConfig(level=logging.DEBUG)

DATABASE = 'reviews.db'

# Maksymalny rozmiar pliku w bajtach (np. 5 MB)
MAX_FILE_SIZE = 5 * 1024 * 1024

# File upload configuration
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Allowed file extensions and MIME types
ALLOWED_EXTENSIONS = {'pdf'}
ALLOWED_MIME_TYPES = {
    'application/pdf'
}

# Ensure the folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

import requests

# Funkcja ładująca klucz API z pliku tekstowego
def load_api_key_from_txt():
    try:
        with open('virus_total_api.txt', 'r') as f:
            api_key = f.read().strip()  # Odczytaj klucz i usuń ewentualne białe znaki
            return api_key
    except FileNotFoundError:
        raise FileNotFoundError("Plik virus_total_api.txt nie został znaleziony.")
    except Exception as e:
        raise ValueError(f"Wystąpił błąd podczas odczytywania klucza API: {e}")

# Załaduj klucz API VirusTotal z pliku virus_total_api.txt
VIRUSTOTAL_API_KEY = load_api_key_from_txt()

if not VIRUSTOTAL_API_KEY:
    raise ValueError("Brak klucza API VirusTotal. Upewnij się, że plik virus_total_api.txt jest poprawnie skonfigurowany.")

def scan_file_with_virustotal(file_path):
    """Skanuje plik za pomocą VirusTotal API i zwraca status skanowania."""
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': VIRUSTOTAL_API_KEY}
    files = {'file': (file_path, open(file_path, 'rb'))}

    response = requests.post(url, files=files, params=params)

    if response.status_code == 200:
        json_response = response.json()
        scan_id = json_response.get('scan_id')
        return scan_id
    else:
        return None


def check_virustotal_scan(scan_id):
    """Sprawdza raport VirusTotal za pomocą scan_id, zwraca False, jeśli plik jest zainfekowany."""
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': scan_id}

    response = requests.get(url, params=params)

    if response.status_code == 200:
        json_response = response.json()
        # Pobieramy liczbę pozytywnych wyników skanowania
        positives = json_response.get('positives', 0)
        total = json_response.get('total', 0)

        if positives > 0:
            # Jeśli chociaż jeden skaner wykrył zagrożenie, zwracamy False
            app.logger.warning(f"VirusTotal found {positives} positives out of {total} scans.")
            return False, positives, total  # Plik zainfekowany
        else:
            app.logger.info(f"VirusTotal scan is clean ({positives}/{total}).")
            return True, positives, total  # Plik czysty
    else:
        app.logger.error("Failed to retrieve VirusTotal scan report.")
        return False, 0, 0  # Bezpieczne zachowanie — uznajemy za zagrożenie, jeśli nie możemy sprawdzić

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_reviews_table():
    """Tworzy tabelę 'reviews' jeśli nie istnieje."""
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
        app.logger.debug("Tabela 'reviews' została utworzona lub już istnieje.")
    except sqlite3.Error as e:
        app.logger.error(f"Błąd podczas tworzenia tabeli: {e}")
    finally:
        if conn:
            conn.close()

# Wywołaj funkcję tworzenia tabeli przy uruchomieniu aplikacji
create_reviews_table()


def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = hmac.new(app.secret_key.encode(), session.get('user_id', '').encode(),
                                         hashlib.sha256).hexdigest()
    return session['csrf_token']


def validate_csrf_token(token):
    if not app.config['CSRF_PROTECTION_ENABLED']:
        return True
    return hmac.compare_digest(session.get('csrf_token', ''), token)


def get_db_connection():
    conn = apsw.Connection(DATABASE)
    return conn


def escape_html(text):
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&#39;",
        ">": "&gt;",
        "<": "&lt;",
    }
    return "".join(html_escape_table.get(c, c) for c in text)


def get_last_review():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        sql = "SELECT name, email, content, user_id FROM reviews ORDER BY id DESC LIMIT 1"
        cursor.execute(sql)
        row = cursor.fetchone()
    except apsw.SQLError as e:
        # Obsługa przypadku, gdy tabela nie istnieje
        app.logger.error(f"Database error: {e}")
        row = None
    finally:
        cursor.close()
        conn.close()

    if row:
        name = row[0]
        email = row[1]
        content = row[2]
        user_id = row[3]
        if app.config['XSS_PROTECTION_ENABLED']:
            name = escape_html(name)
            email = escape_html(email)
            content = escape_html(content)
            user_id = escape_html(user_id)
        return {'name': name, 'email': email, 'content': content, 'user_id': user_id}
    else:
        return None


@app.before_request
def generate_session_id():
    # Make the session permanent
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


@app.route('/')
def hello():
    return redirect(url_for('index', session_id=session.get('user_id')))


@app.route('/<session_id>')
def index(session_id):
    thank_you_message = session.pop('thank_you_message', None)
    last_review = session.pop('last_review', None) or get_last_review()
    upload_message = session.pop('upload_message', None)  # Pobranie wiadomości z sesji

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

    return render_template('index.html', sqlin_protection_enabled=app.config['SQLIN_PROTECTION_ENABLED'],
                           xss_protection_enabled=app.config['XSS_PROTECTION_ENABLED'],
                           csrf_protection_enabled=app.config['CSRF_PROTECTION_ENABLED'],
                           session_hijack_protection_enabled=app.config['SESSION_HIJACK_PROTECTION_ENABLED'],
                           file_upload_protection_enabled=app.config['FILE_UPLOAD_PROTECTION_ENABLED'],
                           session_id=session_id, thank_you_message=thank_you_message, last_review=last_review, upload_message=upload_message)


@app.route('/toggle-sqlin-protection', methods=['POST'])
def toggle_sqlin_protection():
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    app.config['SQLIN_PROTECTION_ENABLED'] = not app.config['SQLIN_PROTECTION_ENABLED']
    return redirect('/')


@app.route('/toggle-xss-protection', methods=['POST'])
def toggle_xss_protection():
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    app.config['XSS_PROTECTION_ENABLED'] = not app.config['XSS_PROTECTION_ENABLED']
    return redirect('/')


@app.route('/toggle-csrf-protection', methods=['POST'])
def toggle_csrf_protection():
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    app.config['CSRF_PROTECTION_ENABLED'] = not app.config['CSRF_PROTECTION_ENABLED']
    return redirect('/')


@app.route('/toggle-session-hijack-protection', methods=['POST'])
def toggle_session_hijack_protection():
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    app.config['SESSION_HIJACK_PROTECTION_ENABLED'] = not app.config['SESSION_HIJACK_PROTECTION_ENABLED']
    return redirect('/')


@app.route('/toggle-file-upload-protection', methods=['POST'])
def toggle_file_upload_protection():
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    app.config['FILE_UPLOAD_PROTECTION_ENABLED'] = not app.config['FILE_UPLOAD_PROTECTION_ENABLED']
    return redirect('/')


@app.route('/submit-review/<session_id>', methods=['POST'])
def submit_review(session_id):
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)

    app.logger.debug(f"Submit review: URL session_id={session_id}, session user_id={session.get('user_id')}")

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    content = request.form.get('message', '').strip()
    user_id = session_id  # We use the session_id passed in the URL as the user_id

    # Wykonujemy escape tylko wtedy, gdy ochrona przed XSS jest włączona
    if app.config['XSS_PROTECTION_ENABLED']:
        name = escape_html(name)
        email = escape_html(email)
        content = escape_html(content)
        user_id = escape_html(user_id)

    # Logowanie wartości w celu debugowania
    app.logger.debug(f"Review details - Name: {name}, Email: {email}, Content: {content}, User ID: {user_id}")

    if not name or not email or not content or not user_id:
        app.logger.error("One or more review details are missing.")
        abort(400, description="Bad Request: One or more review details are missing.")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        malicious_result = None  # Wynik zapytania SELECT, jeśli istnieje
        if app.config['SQLIN_PROTECTION_ENABLED']:
            # Zabezpieczone zapytanie z parametryzacją
            sql = "INSERT INTO reviews (name, email, content, user_id) VALUES (?, ?, ?, ?)"
            cursor.execute(sql, (name, email, content, user_id))
        else:
            # Złośliwe zapytanie SQL (bez ochrony SQL Injection)
            if "');" in name:
                base_name, sql_injection = name.split("');", 1)
                # Bezpieczne zapytanie INSERT
                sql_safe = (f"INSERT INTO reviews (name, email, content, user_id) "
                            f"VALUES ('{base_name}', '{email}', '{content}', '{user_id}')")
                app.logger.debug(f"Executing safe SQL: {sql_safe}")
                cursor.execute(sql_safe)

                # Wykonanie złośliwego kodu SQL (druga część)
                malicious_sql = sql_injection.strip().replace('--', '')  # Usuwamy komentarze SQL
                app.logger.debug(f"Executing malicious SQL: {malicious_sql}")
                cursor.execute(malicious_sql)

                # Jeśli zapytanie to SELECT, pobierz wyniki
                if malicious_sql.strip().upper().startswith("SELECT"):
                    malicious_result = cursor.fetchall()  # Pobranie wszystkich wyników zapytania

            else:
                # Normalne zapytanie bez złośliwego kodu
                sql = (f"INSERT INTO reviews (name, email, content, user_id) "
                       f"VALUES ('{name}', '{email}', '{content}', '{user_id}')")
                app.logger.debug(f"Executing SQL: {sql}")
                cursor.execute(sql)

    except apsw.SQLError as e:
        app.logger.error(f"Error executing SQL: {e}")
        raise
    finally:
        cursor.close()
        conn.close()

    # Przygotowanie wiadomości z podziękowaniem oraz wyniku zapytania SQL
    if malicious_result:
        app.logger.debug(f"Malicious query result: {malicious_result}")
        # Wyświetlamy wyniki zapytania bez dodatkowego opisu
        result_message = "<br>".join([f"{row[0]} | {row[1]}" for row in malicious_result])
        thank_you_message = f"Thank you for adding your comment, {name}!<br>{result_message}"
    else:
        # Standardowa wiadomość, gdy nie ma złośliwego wyniku
        thank_you_message = f"Thank you for adding your comment, {name}!"

    # Zapisanie ostatniej recenzji
    last_review = {'name': name, 'email': email, 'content': content, 'user_id': user_id}

    # Przekierowanie do strony głównej z wiadomością podziękowania lub wynikami zapytania
    session['thank_you_message'] = thank_you_message
    session['last_review'] = last_review
    return redirect(url_for('index', session_id=session_id))


# File upload route
import magic  # Do sprawdzania MIME typu plików
from werkzeug.utils import secure_filename  # Zabezpieczenie nazwy pliku

# Maksymalny rozmiar pliku w bajtach (np. 5 MB)
MAX_FILE_SIZE = 5 * 1024 * 1024

# Lista dozwolonych typów MIME (np. PDF i obrazy)
ALLOWED_MIME_TYPES = ['application/pdf', 'image/jpeg', 'image/png']


@app.route('/upload', methods=['POST'])
def upload_file():
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
        # Sprawdzenie ochrony przed przesyłaniem plików
        if app.config['FILE_UPLOAD_PROTECTION_ENABLED']:
            # Sprawdzenie typu MIME za pomocą magic
            mime = magic.Magic(mime=True)
            mime_type = mime.from_buffer(file.read(1024))
            file.seek(0)  # Resetowanie wskaźnika pliku po odczycie
            if mime_type not in ALLOWED_MIME_TYPES:
                session['upload_message'] = f"Invalid file type: {mime_type}"
                return redirect(url_for('index', session_id=session.get('user_id')))

            # Sprawdzenie rozmiaru pliku
            file.seek(0, os.SEEK_END)
            file_length = file.tell()
            file.seek(0)
            if file_length > MAX_FILE_SIZE:
                session['upload_message'] = "File is too large"
                return redirect(url_for('index', session_id=session.get('user_id')))

        # Zapis pliku na serwerze
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(file_path)

        # Skanowanie pliku tylko jeśli ochrona przed przesyłaniem plików jest włączona
        if app.config['FILE_UPLOAD_PROTECTION_ENABLED']:
            scan_id = scan_file_with_virustotal(file_path)
            if scan_id:
                # Sprawdzenie raportu VirusTotal
                is_clean, positives, total = check_virustotal_scan(scan_id)
                if not is_clean:
                    # Jeśli plik jest zainfekowany, usuwamy go i informujemy użytkownika
                    os.remove(file_path)  # Usunięcie zainfekowanego pliku
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
            # Jeśli ochrona przed przesyłaniem plików jest wyłączona, po prostu zapisz plik bez skanowania
            session['upload_message'] = f"File {file.filename} uploaded successfully without VirusTotal scan."

        return redirect(url_for('index', session_id=session.get('user_id')))


if __name__ == '__main__':
    app.run(debug=True)
