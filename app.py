# Standard imports
import uuid
import logging
import os
import hmac
import hashlib

# External imports
import apsw
import sqlite3
from flask import Flask, render_template, request, redirect, session, url_for, abort

app = Flask(__name__)
app.config['SQLIN_PROTECTION_ENABLED'] = True
app.config['XSS_PROTECTION_ENABLED'] = True
app.config['SESSION_HIJACK_PROTECTION_ENABLED'] = True
app.config['CSRF_PROTECTION_ENABLED'] = True
app.secret_key = 'super_secret_key'

logging.basicConfig(level=logging.DEBUG)

DATABASE = 'reviews.db'

# File upload configuration
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


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
                           session_hijack_protection_enabled=app.config['SESSION_HIJACK_PROTECTION_ENABLED'],
                           csrf_protection_enabled=app.config['CSRF_PROTECTION_ENABLED'],
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


@app.route('/toggle-session-hijack-protection', methods=['POST'])
def toggle_session_hijack_protection():
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    app.config['SESSION_HIJACK_PROTECTION_ENABLED'] = not app.config['SESSION_HIJACK_PROTECTION_ENABLED']
    return redirect('/')


@app.route('/toggle-csrf-protection', methods=['POST'])
def toggle_csrf_protection():
    if not validate_csrf_token(request.form.get('csrf_token')):
        abort(403)
    app.config['CSRF_PROTECTION_ENABLED'] = not app.config['CSRF_PROTECTION_ENABLED']
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
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'ebook-file' not in request.files:
        session['upload_message'] = "No file part"
        return redirect(url_for('index', session_id=session.get('user_id')))

    file = request.files['ebook-file']
    if file.filename == '':
        session['upload_message'] = "No selected file"
        return redirect(url_for('index', session_id=session.get('user_id')))

    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        session['upload_message'] = f"File {file.filename} uploaded successfully"
        return redirect(url_for('index', session_id=session.get('user_id')))


if __name__ == '__main__':
    app.run(debug=True)
