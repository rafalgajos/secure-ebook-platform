from flask import Flask, render_template, request, redirect, url_for
import os

app = Flask(__name__)

# Folder na przesłane pliki
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Upewnij się, że folder na przesłane pliki istnieje
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


@app.route('/')
def hello_world():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'ebook-file' not in request.files:
        return "No file part", 400

    file = request.files['ebook-file']
    if file.filename == '':
        return "No selected file", 400

    if file:
        # Zapisz plik do folderu uploads
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        return f"File {file.filename} uploaded successfully", 200


if __name__ == '__main__':
    app.run(debug=True)
