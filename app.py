# Standard imports
import logging
import uuid  # To generate a user_id for each review
import os  # To handle file system operations for the upload folder
import apsw
from flask import Flask, render_template, request, redirect, url_for, abort

app = Flask(__name__)
app.secret_key = 'super_secret_key'

logging.basicConfig(level=logging.DEBUG)

DATABASE = 'reviews.db'

# Folder where uploaded files will be stored
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the uploads folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def get_db_connection():
    conn = apsw.Connection(DATABASE)
    return conn


def get_last_review():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        sql = "SELECT name, email, content, user_id FROM reviews ORDER BY id DESC LIMIT 1"
        cursor.execute(sql)
        row = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if row:
        return {'name': row[0], 'email': row[1], 'content': row[2], 'user_id': row[3]}
    else:
        return None


@app.route('/')
def index():
    # Get the last review from the database
    last_review = get_last_review()
    # Get the upload message from the request arguments
    upload_message = request.args.get('upload_message', None)
    return render_template('index.html',
                           sqlin_protection_enabled=app.config['SQLIN_PROTECTION_ENABLED'],
                           last_review=last_review,
                           upload_message=upload_message)


@app.route('/toggle-sqlin-protection', methods=['POST'])
def toggle_sqlin_protection():
    # Toggle SQL injection protection on or off
    app.config['SQLIN_PROTECTION_ENABLED'] = not app.config['SQLIN_PROTECTION_ENABLED']
    return redirect('/')


@app.route('/submit-review', methods=['POST'])
def submit_review():
    # Extract form data
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    content = request.form.get('message', '').strip()

    # Generate a new user_id using UUID
    user_id = str(uuid.uuid4())

    # Validate the form input
    if not name or not email or not content:
        app.logger.error("One or more review details are missing.")
        abort(400, description="Bad Request: One or more review details are missing.")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # If SQL injection protection is enabled, use parameterized queries
        if app.config['SQLIN_PROTECTION_ENABLED']:
            sql = "INSERT INTO reviews (name, email, content, user_id) VALUES (?, ?, ?, ?)"
            cursor.execute(sql, (name, email, content, user_id))
        else:
            # Vulnerable query to simulate SQL injection
            sql = f"INSERT INTO reviews (name, email, content, user_id) VALUES ('{name}', '{email}', '{content}', '{user_id}')"
            app.logger.debug(f"Executing SQL: {sql}")
            cursor.execute(sql)
    except Exception as e:
        app.logger.error(f"Error executing SQL: {e}")
        raise
    finally:
        cursor.close()
        conn.close()

    # Redirect back to the home page after submitting the review
    return redirect(url_for('index'))


# Add the upload functionality back
@app.route('/upload', methods=['POST'])
def upload_file():
    # Handle file uploads
    if 'ebook-file' not in request.files:
        return redirect(url_for('index', upload_message="No file part"))

    file = request.files['ebook-file']
    if file.filename == '':
        return redirect(url_for('index', upload_message="No selected file"))

    if file:
        # Save the file to the uploads folder
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        # Redirect back to the index with a success message
        return redirect(url_for('index', upload_message=f"File {file.filename} uploaded successfully"))


if __name__ == '__main__':
    # Enable SQL Injection protection by default
    app.config['SQLIN_PROTECTION_ENABLED'] = True
    app.run(debug=True)
