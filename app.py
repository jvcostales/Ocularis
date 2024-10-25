from flask import Flask, render_template, request, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import psycopg2

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
            conn.rollback()
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
            return redirect(url_for('dashboard'))
        else:
            return 'Invalid username or password'
        
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return f'Welcome, {current_user.username}!'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)