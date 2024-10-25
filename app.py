from flask import Flask, render_template, request, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import psycopg2
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'v$2nG#8mKqT3@z!bW7e^d6rY*9xU&j!P'
login_manager = LoginManager()
login_manager.init_app(app)

conn = psycopg2.connect(host="dpg-cs146g68ii6s73cv89q0-a.oregon-postgres.render.com", dbname="ocular_db", user="ocular_db_user", password="j9nq5DjPbFZSJ8HhQmdbFRmF1s86fRui", port=5432)

cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);
""")

cur.execute(""" 
CREATE TABLE IF NOT EXISTS images (
    image_id SERIAL PRIMARY KEY,
    id INT NOT NULL,
    image_url VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (id) REFERENCES users(id) ON DELETE CASCADE
);
""")

conn.commit()

cur.close()
conn.close()

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    conn = psycopg2.connect(host="dpg-cs146g68ii6s73cv89q0-a.oregon-postgres.render.com", dbname="ocular_db", user="ocular_db_user", password="j9nq5DjPbFZSJ8HhQmdbFRmF1s86fRui", port=5432)
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()
    if user:
        return User(id=user[0], username=user[1], password=user[2])
    return None

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        conn = psycopg2.connect(host="dpg-cs146g68ii6s73cv89q0-a.oregon-postgres.render.com", dbname="ocular_db", user="ocular_db_user", password="j9nq5DjPbFZSJ8HhQmdbFRmF1s86fRui", port=5432)
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
            conn.commit()
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error: {e}")
        finally:
            cur.close()
            conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = psycopg2.connect(host="dpg-cs146g68ii6s73cv89q0-a.oregon-postgres.render.com", dbname="ocular_db", user="ocular_db_user", password="j9nq5DjPbFZSJ8HhQmdbFRmF1s86fRui", port=5432)
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user[2], password):
            login_user(User(id=user[0], username=user[1], password=user[2]))
            return redirect(url_for('feed'))
        else:
            return 'Invalid username or password'
    return render_template('login.html')

@app.route('/feed')
@login_required
def feed():
    return render_template('feed.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Define the allowed extensions for the uploaded files
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Function to check if the file has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_image():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'image' not in request.files:
            return 'No file part'
        
        file = request.files['image']
        
        # If the user does not select a file, the browser submits an empty file without a filename
        if file.filename == '':
            return 'No selected file'
        
        if file and allowed_file(file.filename):
            # Secure the filename and save the image
            filename = secure_filename(file.filename)
            file_path = os.path.join('/var/data', filename)  # Change this to your directory on Render
            file.save(file_path)

            # Prepare the image URL (this depends on your Render URL structure)
            image_url = f"https://<your-service-name>.onrender.com//var/data/{filename}"

            # Store the image URL in PostgreSQL
            conn = psycopg2.connect(host="dpg-cs146g68ii6s73cv89q0-a.oregon-postgres.render.com", dbname="ocular_db", user="ocular_db_user", password="j9nq5DjPbFZSJ8HhQmdbFRmF1s86fRui", port=5432)
            cur = conn.cursor()
            cur.execute("INSERT INTO images (id, image_url) VALUES (%s, %s)", (current_user.id, image_url))
            conn.commit()
            cur.close()
            conn.close()

            return redirect(url_for('feed'))  # Redirect to feed after upload
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)