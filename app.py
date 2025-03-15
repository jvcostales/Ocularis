from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import psycopg2
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = 'v$2nG#8mKqT3@z!bW7e^d6rY*9xU&j!P'
login_manager = LoginManager()
login_manager.init_app(app)

conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", dbname="ocularis_db", user="ocularis_db_user", password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", port=5432)

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

cur.execute(""" 
CREATE TABLE IF NOT EXISTS likes (
    like_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    image_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (image_id) REFERENCES images(image_id) ON DELETE CASCADE,
    UNIQUE (user_id, image_id)
);
""")

cur.execute(""" 
CREATE TABLE IF NOT EXISTS comments (
    comment_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    image_id INT NOT NULL,
    comment_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (image_id) REFERENCES images(image_id) ON DELETE CASCADE
);
""")

cur.execute(""" 
CREATE TABLE IF NOT EXISTS comment_likes (
    comment_like_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    comment_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (comment_id) REFERENCES comments(comment_id) ON DELETE CASCADE,
    UNIQUE (user_id, comment_id) -- prevent duplicate likes
);
""")

cur.execute(""" 
CREATE TABLE IF NOT EXISTS notifications (
    notification_id SERIAL PRIMARY KEY,
    recipient_id INT NOT NULL,
    actor_id INT NOT NULL,
    image_id INT NOT NULL,
    action_type VARCHAR(50) NOT NULL, -- 'like' or 'comment'
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (image_id) REFERENCES images(image_id) ON DELETE CASCADE
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
    conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", dbname="ocularis_db", user="ocularis_db_user", password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", port=5432)
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

        conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", dbname="ocularis_db", user="ocularis_db_user", password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", port=5432)
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

        conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", dbname="ocularis_db", user="ocularis_db_user", password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", port=5432)
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
    conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
                            dbname="ocularis_db", 
                            user="ocularis_db_user", 
                            password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
                            port=5432)
    cur = conn.cursor()
    
    try:
        cur.execute("""
            SELECT images.image_id, images.image_url, 
                COALESCE(like_count, 0), images.id
            FROM images 
            LEFT JOIN (SELECT image_id, COUNT(*) AS like_count FROM likes GROUP BY image_id) AS likes 
            ON images.image_id = likes.image_id
            ORDER BY images.created_at DESC
        """)
        images = cur.fetchall()

        cur.execute("""
            SELECT comments.comment_id, comments.image_id, users.username, comments.comment_text, comments.created_at,
                COALESCE(like_count, 0) as like_count
            FROM comments
            JOIN users ON comments.user_id = users.id
            LEFT JOIN (
                SELECT comment_id, COUNT(*) as like_count
                FROM comment_likes
                GROUP BY comment_id
            ) as cl ON comments.comment_id = cl.comment_id
            ORDER BY comments.created_at ASC
        """)
        comments = cur.fetchall()

    finally:
        cur.close()
        conn.close()

    return render_template('feed.html', images=images, comments=comments)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/images/<filename>')
def serve_images(filename):
    return send_from_directory('/var/data', filename)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_image():
    if request.method == 'POST':
        if 'image' not in request.files:
            return 'No file part'
        
        file = request.files['image']
        
        if file.filename == '':
            return 'No selected file'
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join('/var/data', filename)
            file.save(file_path)    

            image_url = f"https://ocular-zmcu.onrender.com/images/{filename}"

            conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", dbname="ocularis_db", user="ocularis_db_user", password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", port=5432)
            cur = conn.cursor()
            cur.execute("INSERT INTO images (id, image_url) VALUES (%s, %s)", (current_user.id, image_url))
            conn.commit()
            cur.close()
            conn.close()

            return redirect(url_for('feed'))
    return render_template('upload.html')


@app.route('/like/<int:image_id>', methods=['POST'])
@login_required
def like_image(image_id):
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()

    try:
        # Check if the user has already liked the image
        cur.execute("SELECT * FROM likes WHERE user_id = %s AND image_id = %s", (current_user.id, image_id))
        existing_like = cur.fetchone()

        if existing_like:
            # Unlike the image
            cur.execute("DELETE FROM likes WHERE user_id = %s AND image_id = %s", (current_user.id, image_id))
        else:
            # Like the image
            cur.execute("INSERT INTO likes (user_id, image_id) VALUES (%s, %s)", (current_user.id, image_id))

            # Get the image owner
            cur.execute("SELECT id FROM images WHERE image_id = %s", (image_id,))
            owner = cur.fetchone()

            # Create notification if the liker is not the owner
            if owner and owner[0] != current_user.id:
                cur.execute("""
                    INSERT INTO notifications (recipient_id, actor_id, image_id, action_type)
                    VALUES (%s, %s, %s, 'like')
                """, (owner[0], current_user.id, image_id))

        conn.commit()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('feed'))

@app.route('/comment/<int:image_id>', methods=['POST'])
@login_required
def post_comment(image_id):
    comment_text = request.form['comment']
    
    if not comment_text.strip():
        return redirect(url_for('feed'))

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()
    
    try:
        # Insert the comment
        cur.execute("INSERT INTO comments (user_id, image_id, comment_text) VALUES (%s, %s, %s)", 
                    (current_user.id, image_id, comment_text))

        # Get the image owner
        cur.execute("SELECT id FROM images WHERE image_id = %s", (image_id,))
        owner = cur.fetchone()

        # Create a notification if commenter is not the owner
        if owner and owner[0] != current_user.id:
            cur.execute("""
                INSERT INTO notifications (recipient_id, actor_id, image_id, action_type)
                VALUES (%s, %s, %s, 'comment')
            """, (owner[0], current_user.id, image_id))

        conn.commit()
    finally:
        cur.close()
        conn.close()
    
    return redirect(url_for('feed'))


@app.route('/delete/<int:image_id>', methods=['POST'])
@login_required
def delete_image(image_id):
    conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
                            dbname="ocularis_db", 
                            user="ocularis_db_user", 
                            password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
                            port=5432)
    cur = conn.cursor()

    try:
        # Ensure only the owner can delete their post
        cur.execute("SELECT id, image_url FROM images WHERE image_id = %s", (image_id,))
        image = cur.fetchone()

        if image and image[0] == current_user.id:
            cur.execute("DELETE FROM images WHERE image_id = %s", (image_id,))
            conn.commit()

            # Delete image file (optional)
            filename = image[1].split("/")[-1]  # Extract filename from URL
            file_path = os.path.join('/var/data', filename)
            if os.path.exists(file_path):
                os.remove(file_path)

        else:
            return "Unauthorized action", 403

    finally:
        cur.close()
        conn.close()

    return redirect(url_for('feed'))

@app.route('/comment/like/<int:comment_id>', methods=['POST'])
@login_required
def like_comment(comment_id):
    conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
                            dbname="ocularis_db", 
                            user="ocularis_db_user", 
                            password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
                            port=5432)
    cur = conn.cursor()
    try:
        # Check if the user already liked the comment
        cur.execute("SELECT * FROM comment_likes WHERE user_id = %s AND comment_id = %s", 
                    (current_user.id, comment_id))
        existing_like = cur.fetchone()

        if existing_like:
            cur.execute("DELETE FROM comment_likes WHERE user_id = %s AND comment_id = %s", 
                        (current_user.id, comment_id))
        else:
            cur.execute("INSERT INTO comment_likes (user_id, comment_id) VALUES (%s, %s)", 
                        (current_user.id, comment_id))
        conn.commit()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('feed'))

@app.route('/notifications')
@login_required
def notifications():
    conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
                            dbname="ocularis_db", 
                            user="ocularis_db_user", 
                            password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
                            port=5432)
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT users.username, notifications.action_type, notifications.image_id, notifications.created_at
            FROM notifications
            JOIN users ON notifications.actor_id = users.id
            WHERE notifications.recipient_id = %s
            ORDER BY notifications.created_at DESC
        """, (current_user.id,))
        notifs = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    return render_template('notifications.html', notifications=notifs)


if __name__ == '__main__':
    app.run(debug=True)