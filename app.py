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

conn.commit()
cur.close()
conn.close()

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
                   COALESCE(like_count, 0) 
            FROM images 
            LEFT JOIN (SELECT image_id, COUNT(*) AS like_count FROM likes GROUP BY image_id) AS likes 
            ON images.image_id = likes.image_id
            ORDER BY images.created_at DESC
        """)
        images = cur.fetchall()
        
        cur.execute("""
            SELECT comments.image_id, comments.comment_text, users.username 
            FROM comments 
            JOIN users ON comments.user_id = users.id 
            ORDER BY comments.created_at ASC
        """)
        comments = cur.fetchall()
    finally:
        cur.close()
        conn.close()

    comments_dict = {}
    for comment in comments:
        image_id = comment[0]
        if image_id not in comments_dict:
            comments_dict[image_id] = []
        comments_dict[image_id].append((comment[2], comment[1]))

    return render_template('feed.html', images=images, comments=comments_dict)

@app.route('/comment/<int:image_id>', methods=['POST'])
@login_required
def comment_image(image_id):
    comment_text = request.form['comment']
    
    if not comment_text.strip():
        return redirect(url_for('feed'))
    
    conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
                            dbname="ocularis_db", 
                            user="ocularis_db_user", 
                            password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
                            port=5432)
    cur = conn.cursor()
    
    try:
        cur.execute("INSERT INTO comments (user_id, image_id, comment_text) VALUES (%s, %s, %s)", 
                    (current_user.id, image_id, comment_text))
        conn.commit()
    finally:
        cur.close()
        conn.close()
    
    return redirect(url_for('feed'))

if __name__ == '__main__':
    app.run(debug=True)