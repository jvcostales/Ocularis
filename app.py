from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, flash, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import psycopg2
from werkzeug.utils import secure_filename
import os
import smtplib
import secrets
from email.mime.text import MIMEText
from search import search_bp
from recommender import get_similar_users
from datetime import datetime, timedelta, timezone
import pandas as pd
import json
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = 'v$2nG#8mKqT3@z!bW7e^d6rY*9xU&j!P'
app.register_blueprint(search_bp)
login_manager = LoginManager()
login_manager.init_app(app)

with open('data/countries.json') as f:
    countries = json.load(f)

with open('data/states.json') as f:
    states = json.load(f)

with open('data/cities.json') as f:
    cities = json.load(f)

app.config['COUNTRIES'] = countries
app.config['STATES'] = states
app.config['CITIES'] = cities

conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", dbname="ocularis_db", user="ocularis_db_user", password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", port=5432)

cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    verification_token TEXT,
    reset_token TEXT,
    skills TEXT[],            -- Array of skills (e.g., ['UI/UX Design', 'Branding'])
    preferences TEXT[],       -- Array of preferences (e.g., ['Illustration', '3D Design'])
    experience_level INT,      -- e.g., 1 = beginner, 2 = intermediate, 3 = advanced, 4 = expert
    country TEXT,
    state TEXT,
    city TEXT,
    role VARCHAR(100),
    facebook VARCHAR(100),
    instagram VARCHAR(100),
    x VARCHAR(100),
    linkedin VARCHAR(100),
    telegram VARCHAR(100),
    profile_pic VARCHAR(255),  -- NEW: stores the path or URL to the profile picture
    is_profile_complete BOOLEAN DEFAULT FALSE
);
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS images (
    image_id SERIAL PRIMARY KEY,
    id INT NOT NULL,
    image_url VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    collaborator_id INT,
    caption TEXT,
    FOREIGN KEY (id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (collaborator_id) REFERENCES users(id)
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
    image_id INT, -- made nullable for notifications that don't relate to images
    action_type VARCHAR(50) NOT NULL, -- e.g., 'like', 'comment', 'collab_check'
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (image_id) REFERENCES images(image_id) ON DELETE CASCADE
);
""")


cur.execute(""" 
CREATE TABLE IF NOT EXISTS image_tags (
    id SERIAL PRIMARY KEY,
    image_id INT REFERENCES images(image_id) ON DELETE CASCADE,
    tag VARCHAR(50) NOT NULL
);
""")

cur.execute(""" 
CREATE TABLE IF NOT EXISTS friend_requests (
    request_id SERIAL PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    status VARCHAR(10) CHECK (status IN ('pending', 'accepted', 'rejected')) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (sender_id, receiver_id)
);
""")

cur.execute(""" 
CREATE TABLE IF NOT EXISTS friends (
    user1_id INT NOT NULL,
    user2_id INT NOT NULL,
    friended_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (user1_id, user2_id),
    FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE,
    CHECK (user1_id <> user2_id)
);
""")

cur.execute(""" 
CREATE TABLE IF NOT EXISTS collab_actions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

cur.execute(""" 
CREATE TABLE IF NOT EXISTS recent_matches (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    matched_user_id INT REFERENCES users(id),
    matched_at TIMESTAMP DEFAULT NOW()
);
""")

cur.execute(""" 
CREATE TABLE IF NOT EXISTS image_collaborators (
    image_id INT REFERENCES images(image_id) ON DELETE CASCADE,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (image_id, user_id)
);
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS saved_posts (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL,
    image_id INT NOT NULL,
    saved_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (user_id, image_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (image_id) REFERENCES images(image_id) ON DELETE CASCADE
);
""")

conn.commit()

cur.close()
conn.close()

class User(UserMixin):
    def __init__(self, id, first_name, last_name, email, password, verified=False):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.password = password
        self.verified = verified


@login_manager.user_loader
def load_user(user_id):
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()
    cur.execute("SELECT id, first_name, last_name, email, password, verified FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    cur.close()
    conn.close()

    if user:
        return User(
            id=user[0],
            first_name=user[1],
            last_name=user[2],
            email=user[3],
            password=user[4],
            verified=user[5]
        )
    return None

def send_verification_email(recipient_email, token):
    verification_link = f"https://ocular-zmcu.onrender.com/verify-email/{token}"
    subject = "Verify your email for Ocularis"
    body = f"Hi there! Please click the link below to verify your email:\n{verification_link}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = "jadynicolecostales2@gmail.com"
    msg["To"] = recipient_email

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login("jadynicolecostales2@gmail.com", "erxt hevv irmn rjyy")
            server.send_message(msg)
    except Exception as e:
        app.logger.error(f"Failed to send email: {e}")


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        raw_password = request.form.get('password')

        # Basic validation
        if not first_name or not last_name or not email or not raw_password:
            return "All fields are required."
        if len(raw_password) < 6:
            return "Password must be at least 6 characters long."

        password = generate_password_hash(raw_password)
        token = secrets.token_urlsafe(32)

        try:
            conn = psycopg2.connect(
                host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
                dbname="ocularis_db",
                user="ocularis_db_user",
                password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
                port=5432
            )
            cur = conn.cursor()

            # Check if email already exists
            cur.execute("SELECT 1 FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                return "Email already exists."

            # Insert user
            cur.execute("""
                INSERT INTO users (first_name, last_name, email, password, verification_token, verified)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (first_name, last_name, email, password, token, False))

            user_id = cur.fetchone()[0]
            conn.commit()

            # Now send email
            send_verification_email(email, token)

            return "Check your email to verify your account."
        except Exception as e:
            app.logger.error(f"Signup error: {e}")
            return "An error occurred. Please try again."
        finally:
            if 'cur' in locals():
                cur.close()
            if 'conn' in locals():
                conn.close()

    return render_template('signup.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        conn = psycopg2.connect(
            host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
            dbname="ocularis_db",
            user="ocularis_db_user",
            password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
            port=5432
        )
        cur = conn.cursor()

        # Check token
        cur.execute("SELECT id FROM users WHERE verification_token = %s", (token,))
        user = cur.fetchone()
        if not user:
            return "Invalid or expired token."

        # Mark as verified
        cur.execute("""
            UPDATE users
            SET verified = TRUE, verification_token = NULL
            WHERE id = %s
        """, (user[0],))
        conn.commit()
        return "Email verified! You can now log in."
    except Exception as e:
        app.logger.error(f"Verification error: {e}")
        return "An error occurred during verification."
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = psycopg2.connect(
            host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
            dbname="ocularis_db",
            user="ocularis_db_user",
            password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
            port=5432
        )
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user[4], password):  # password is at index 4
            user_obj = User(id=user[0], first_name=user[1], last_name=user[2], email=user[3], password=user[4])
            login_user(user_obj)

            return redirect(url_for('feed'))
        else:
            return 'Invalid email or password'

    return render_template('login.html')

@app.route('/api/setup-profile', methods=['POST'])
@login_required
def api_setup_profile():
    skills = request.form.getlist('skills')
    prefs = request.form.getlist('preferences')
    level = int(request.form['experience_level'])
    role = request.form['role']
    facebook = request.form['facebook']
    instagram = request.form['instagram']
    x = request.form['x']
    linkedin = request.form['linkedin']
    telegram = request.form['telegram']
    country = request.form['country']
    state = request.form['state']
    city = request.form['city']

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()
    cur.execute("""
        UPDATE users
        SET skills = %s,
            preferences = %s,
            experience_level = %s,
            role = %s,
            facebook = %s,
            instagram = %s,
            x = %s,
            linkedin = %s,
            telegram = %s,
            country = %s,
            state = %s,
            city = %s
        WHERE id = %s
    """, (skills, prefs, level, role, facebook, instagram, x, linkedin, telegram, country, state, city, current_user.id))

    cur.execute("""
    UPDATE users
    SET is_profile_complete = TRUE
    WHERE id = %s
""", (current_user.id,))
    
    conn.commit()
    cur.close()
    conn.close()

    return jsonify({'success': True, 'redirect_url': url_for('feed')})

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", dbname="ocularis_db", user="ocularis_db_user", password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", port=5432)
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if user:
            token = secrets.token_urlsafe(32)
            # Store token
            cur.execute("UPDATE users SET reset_token = %s WHERE email = %s", (token, email))
            conn.commit()

            reset_link = url_for('reset_password', token=token, _external=True)
            send_reset_email(email, reset_link)

        cur.close()
        conn.close()
        return "If your email exists, a reset link has been sent."
    return render_template('forgot_password.html')

def send_reset_email(to_email, reset_link):
    sender_email = "jadynicolecostales2@gmail.com"
    sender_password = "erxt hevv irmn rjyy"

    msg = MIMEText(f'Click the link to reset your password: {reset_link}')
    msg['Subject'] = 'Password Reset - Ocularis'
    msg['From'] = sender_email
    msg['To'] = to_email

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
    except Exception as e:
        print(f"Email failed: {e}")

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        new_password = request.form['password']
        hashed = generate_password_hash(new_password)

        conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", dbname="ocularis_db", user="ocularis_db_user", password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", port=5432)
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE reset_token = %s", (token,))
        user = cur.fetchone()

        if user:
            cur.execute("UPDATE users SET password = %s, reset_token = NULL WHERE reset_token = %s",
                        (hashed, token))
            conn.commit()
            cur.close()
            conn.close()
            return redirect(url_for('login'))

        cur.close()
        conn.close()
        return "Invalid or expired token."
    return render_template('reset_password.html')

@app.route('/feed', methods=['GET', 'POST'])
@login_required
def feed():

    user_id = current_user.id
    
    tags = [
        "Typography", "Branding", "Advertising", "Graphic Design", "Illustration",
        "3D Design", "Animation", "Packaging", "Infographics", "UI/UX Design"
    ]

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    # Fetch matched users to show in collaborator select list
    cur.execute("""
        SELECT u.id, u.first_name, u.last_name
        FROM recent_matches rm
        JOIN users u ON rm.matched_user_id = u.id
        WHERE rm.user_id = %s
        ORDER BY rm.matched_at DESC
    """, (current_user.id,))
    matched_users = cur.fetchall()

    if request.method == 'POST':
        if 'image' not in request.files:
            return 'No file part'
        
        file = request.files['image']
        caption = request.form.get('caption', '')
        selected_tags = request.form.getlist('tags')
        collaborator_id = request.form.get('collaborator')  # This will be None if not selected
        
        if file.filename == '':
            return 'No selected file'
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join('/var/data', filename)
            file.save(file_path)

            image_url = f"https://ocular-zmcu.onrender.com/images/{filename}"

            conn = psycopg2.connect(
                host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
                dbname="ocularis_db", 
                user="ocularis_db_user", 
                password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
                port=5432
            )
            cur = conn.cursor()

            # Insert collaborators (if any)
            if collaborator_id:
                cur.execute(
                    "INSERT INTO images (id, image_url, caption, collaborator_id) VALUES (%s, %s, %s, %s) RETURNING image_id",
                    (current_user.id, image_url, caption, collaborator_id)
                )
            else:
                cur.execute(
                    "INSERT INTO images (id, image_url, caption) VALUES (%s, %s, %s) RETURNING image_id",
                    (current_user.id, image_url, caption)
                )

            image_id = cur.fetchone()[0]

            for tag in selected_tags:
                cur.execute("INSERT INTO image_tags (image_id, tag) VALUES (%s, %s)", (image_id, tag))  
  
            conn.commit()
            cur.close()
            conn.close()

            return redirect(url_for('feed'))

    # Fetch feed content, comments, notifications, and friend requests
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    try:
        # Fetch images
        # Fetch images with author and collaborator names
        cur.execute("""
            SELECT 
                images.image_id,              -- 0
                images.image_url,             -- 1
                images.caption,               -- 2
                COALESCE(like_count, 0),      -- 3
                images.id,                    -- 4 (author's user ID)
                author.first_name,            -- 5
                author.last_name,             -- 6
                images.created_at,            -- 7
                collaborator.id,              -- 8 (collaborator's user ID)
                collaborator.first_name,      -- 9
                collaborator.last_name        -- 10
            FROM images
            JOIN users AS author ON images.id = author.id
            LEFT JOIN users AS collaborator ON images.collaborator_id = collaborator.id
            LEFT JOIN (
                SELECT image_id, COUNT(*) AS like_count 
                FROM likes 
                GROUP BY image_id
            ) AS likes 
            ON images.image_id = likes.image_id
            ORDER BY images.created_at DESC;
        """)
        images = cur.fetchall()

        # Fetch comments
        cur.execute("""
            SELECT comments.comment_id, comments.image_id, 
                   users.first_name || ' ' || users.last_name AS display_name, 
                   comments.comment_text, comments.created_at,
                   COALESCE(like_count, 0) AS like_count, comments.user_id
            FROM comments
            JOIN users ON comments.user_id = users.id
            LEFT JOIN (
                SELECT comment_id, COUNT(*) AS like_count
                FROM comment_likes
                GROUP BY comment_id
            ) AS cl ON comments.comment_id = cl.comment_id
            ORDER BY comments.created_at ASC
        """)
        comments = cur.fetchall()

        # Fetch notifications
        cur.execute("""
            SELECT 
                users.first_name || ' ' || users.last_name AS display_name,
                notifications.action_type,
                notifications.image_id,
                notifications.created_at,
                notifications.actor_id
            FROM notifications
            JOIN users ON notifications.actor_id = users.id
            WHERE notifications.recipient_id = %s
            ORDER BY notifications.created_at DESC
        """, (current_user.id,))

        notifications = cur.fetchall()


        # Fetch friend requests
        cur.execute("""
            SELECT fr.request_id, fr.sender_id, u.first_name, u.last_name, fr.created_at
            FROM friend_requests fr
            JOIN users u ON fr.sender_id = u.id
            WHERE fr.receiver_id = %s AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
        """, (current_user.id,))
        requests = cur.fetchall()

        # Fetch likes for each image
        likes_data = {}
        for image in images:
            image_id = image[0]
            cur.execute("""
                SELECT u.first_name || ' ' || u.last_name AS display_name, l.created_at
                FROM likes l
                JOIN users u ON l.user_id = u.id
                WHERE l.image_id = %s
                ORDER BY l.created_at DESC
            """, (image_id,))
            likes = cur.fetchall()
            likes_data[image_id] = likes

        # Fetch likes for each comment
        comment_likes_data = {}
        for comment in comments:
            comment_id = comment[0]
            cur.execute("""
                SELECT u.first_name || ' ' || u.last_name AS display_name, cl.created_at
                FROM comment_likes cl
                JOIN users u ON cl.user_id = u.id
                WHERE cl.comment_id = %s
                ORDER BY cl.created_at DESC
            """, (comment_id,))
            comment_likes = cur.fetchall()
            comment_likes_data[comment_id] = comment_likes

        #setup_profile
        cur.execute("SELECT is_profile_complete FROM users WHERE id = %s", (current_user.id,))
        is_complete = cur.fetchone()[0]

        # Fetch the saved image IDs for the user
        cur.execute("""
            SELECT image_id FROM saved_posts WHERE user_id = %s
        """, (user_id,))
        saved_image_ids = [row[0] for row in cur.fetchall()]

    finally:
        cur.close()
        conn.close()

    categories = [
        "Typography", "Branding", "Advertising", "Graphic Design", "Illustration",
        "3D Design", "Animation", "Packaging", "Infographics", "UI/UX Design"
    ]

    experience_levels = [
        (1, "Beginner"),
        (2, "Intermediate"),
        (3, "Advanced"),
        (4, "Expert")
    ]

    today = datetime.today()

    return render_template(
        'feed.html',
        current_page='feed',
        tags=tags,
        matched_users=matched_users,
        images=images,
        comments=comments,
        notifications=notifications,
        requests=requests,
        likes_data=likes_data,
        comment_likes_data=comment_likes_data,
        show_profile_modal=not is_complete,
        categories=categories,
        experience_levels=experience_levels,
        countries=app.config['COUNTRIES'],
        states=app.config['STATES'],
        cities=app.config['CITIES'],
        verified=current_user.verified,
        today=today,
        saved_image_ids=saved_image_ids
    )

@app.route('/post/<int:image_id>')
@login_required
def view_post(image_id):
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    try:
        # Fetch a single image by image_id
        cur.execute("""
            SELECT images.image_id, images.image_url, images.caption,
                   COALESCE(like_count, 0), images.id, users.first_name, users.last_name, images.created_at
            FROM images 
            JOIN users ON images.id = users.id
            LEFT JOIN (
                SELECT image_id, COUNT(*) AS like_count 
                FROM likes 
                GROUP BY image_id
            ) AS likes 
            ON images.image_id = likes.image_id
            WHERE images.image_id = %s
        """, (image_id,))
        image = cur.fetchone()

        if not image:
            abort(404)

        # Fetch comments for that image
        cur.execute("""
            SELECT comments.comment_id, comments.image_id, 
                   users.first_name || ' ' || users.last_name AS display_name, 
                   comments.comment_text, comments.created_at,
                   COALESCE(like_count, 0) AS like_count, comments.user_id
            FROM comments
            JOIN users ON comments.user_id = users.id
            LEFT JOIN (
                SELECT comment_id, COUNT(*) AS like_count
                FROM comment_likes
                GROUP BY comment_id
            ) AS cl ON comments.comment_id = cl.comment_id
            WHERE comments.image_id = %s
            ORDER BY comments.created_at ASC
        """, (image_id,))
        comments = cur.fetchall()

        # Likes for the image
        cur.execute("""
            SELECT u.first_name || ' ' || u.last_name AS display_name, l.created_at
            FROM likes l
            JOIN users u ON l.user_id = u.id
            WHERE l.image_id = %s
            ORDER BY l.created_at DESC
        """, (image_id,))
        likes = cur.fetchall()
        likes_data = {image_id: likes}

        # Likes for each comment
        comment_likes_data = {}
        for comment in comments:
            comment_id = comment[0]
            cur.execute("""
                SELECT u.first_name || ' ' || u.last_name AS display_name, cl.created_at
                FROM comment_likes cl
                JOIN users u ON cl.user_id = u.id
                WHERE cl.comment_id = %s
                ORDER BY cl.created_at DESC
            """, (comment_id,))
            comment_likes = cur.fetchall()
            comment_likes_data[comment_id] = comment_likes

                # Fetch notifications
        cur.execute("""
            SELECT users.first_name || ' ' || users.last_name AS display_name,
                   notifications.action_type, notifications.image_id, notifications.created_at, notifications.actor_id
            FROM notifications
            JOIN users ON notifications.actor_id = users.id
            WHERE notifications.recipient_id = %s
            ORDER BY notifications.created_at DESC
        """, (current_user.id,))
        notifications = cur.fetchall()

        # Fetch friend requests
        cur.execute("""
            SELECT fr.request_id, fr.sender_id, u.first_name, u.last_name, fr.created_at
            FROM friend_requests fr
            JOIN users u ON fr.sender_id = u.id
            WHERE fr.receiver_id = %s AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
        """, (current_user.id,))
        requests = cur.fetchall()

    finally:
        cur.close()
        conn.close()

    return render_template(
        'post.html',
        image=image,
        comments=comments,
        likes_data=likes_data,
        comment_likes_data=comment_likes_data,
        notifications=notifications,
        requests=requests,
        verified=current_user.verified
    )

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

        # Count current likes BEFORE closing
        cur.execute("SELECT COUNT(*) FROM likes WHERE image_id = %s", (image_id,))
        like_count = cur.fetchone()[0]

        conn.commit()
    finally:
        cur.close()
        conn.close()

    return jsonify({
        'status': 'liked' if not existing_like else 'unliked',
        'like_count': like_count
    })

@app.route('/likes/<int:image_id>', methods=['GET'])
@login_required
def get_image_likes(image_id):
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()

    try:
        cur.execute("""
            SELECT u.first_name || ' ' || u.last_name AS display_name, l.created_at
            FROM likes l
            JOIN users u ON l.user_id = u.id
            WHERE l.image_id = %s
            ORDER BY l.created_at DESC
        """, (image_id,))
        likes = cur.fetchall()

        likers = [{'name': row[0], 'timestamp': row[1].isoformat()} for row in likes]
    finally:
        cur.close()
        conn.close()

    return jsonify({
        'image_id': image_id,
        'likers': likers,
        'like_count': len(likers)
    })

@app.route('/comment/<int:image_id>', methods=['POST'])
@login_required
def post_comment(image_id):
    comment_text = request.json.get('comment')  # Expect JSON from AJAX

    if not comment_text.strip():
        return jsonify({'error': 'Empty comment'}), 400

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
        cur.execute(
            "INSERT INTO comments (user_id, image_id, comment_text) VALUES (%s, %s, %s) RETURNING created_at",
            (current_user.id, image_id, comment_text)
        )
        created_at = cur.fetchone()[0]

        # Get the image owner
        cur.execute("SELECT id FROM images WHERE image_id = %s", (image_id,))
        owner = cur.fetchone()

        if owner and owner[0] != current_user.id:
            cur.execute("""
                INSERT INTO notifications (recipient_id, actor_id, image_id, action_type)
                VALUES (%s, %s, %s, 'comment')
            """, (owner[0], current_user.id, image_id))

        conn.commit()
    finally:
        cur.close()
        conn.close()

    return jsonify({
        'status': 'success',
        'comment': {
            'name': f'{current_user.first_name} {current_user.last_name}',
            'text': comment_text,
            'timestamp': created_at.isoformat()
        }
    })

@app.route('/comment/delete/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()
    
    try:
        # Ensure only the author can delete their comment
        cur.execute("SELECT user_id FROM comments WHERE comment_id = %s", (comment_id,))
        comment = cur.fetchone()

        if comment and comment[0] == current_user.id:
            cur.execute("DELETE FROM comments WHERE comment_id = %s", (comment_id,))
            conn.commit()
        else:
            return "Unauthorized action", 403

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
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()
    try:
        # Check if the user already liked the comment
        cur.execute(
            "SELECT 1 FROM comment_likes WHERE user_id = %s AND comment_id = %s",
            (current_user.id, comment_id)
        )
        existing_like = cur.fetchone()

        if existing_like:
            # User already liked -> unlike
            cur.execute(
                "DELETE FROM comment_likes WHERE user_id = %s AND comment_id = %s",
                (current_user.id, comment_id)
            )
            status = 'unliked'
        else:
            # User has not liked -> like
            cur.execute(
                "INSERT INTO comment_likes (user_id, comment_id) VALUES (%s, %s)",
                (current_user.id, comment_id)
            )
            status = 'liked'

        # Commit the insert/delete
        conn.commit()

        # Get updated like count
        cur.execute("SELECT COUNT(*) FROM comment_likes WHERE comment_id = %s", (comment_id,))
        like_count = cur.fetchone()[0]

    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        return jsonify({'error': str(e)}), 500

    cur.close()
    conn.close()

    return jsonify({
        'status': status,
        'like_count': like_count
    })

@app.route('/comment/likes/<int:comment_id>', methods=['GET'])
@login_required
def get_comment_likes(comment_id):
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()
    try:
        # Optional: Check if comment exists to avoid invalid comment_id
        cur.execute("SELECT 1 FROM comments WHERE comment_id = %s", (comment_id,))
        if not cur.fetchone():
            return jsonify({'error': 'Comment not found'}), 404

        cur.execute("""
            SELECT u.first_name || ' ' || u.last_name AS display_name, cl.created_at
            FROM comment_likes cl
            JOIN users u ON cl.user_id = u.id
            WHERE cl.comment_id = %s
            ORDER BY cl.created_at DESC
        """, (comment_id,))
        likes = cur.fetchall()

        likers = [{'name': row[0], 'timestamp': row[1].isoformat()} for row in likes]
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        conn.close()

    return jsonify({
        'comment_id': comment_id,
        'likers': likers,
        'like_count': len(likers)
    })


@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    current_user_id = current_user.id

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()
    
    # Fetch user details
    cur.execute("SELECT first_name, last_name, role, city, state, country FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()
    role = user[2]
    city = user[3]
    state = user[4]
    country = user[5]

    # Count number of confirmed friends (mutual connections)
    cur.execute("""
        SELECT COUNT(*) FROM friends 
        WHERE user1_id = %s OR user2_id = %s
    """, (user_id, user_id))
    friend_count = cur.fetchone()[0]


    # Fetch images with author and collaborator names for a specific user
    cur.execute("""
        SELECT 
            images.image_id,              -- 0
            images.image_url,             -- 1
            images.caption,               -- 2
            COALESCE(like_count, 0),      -- 3
            images.id,                    -- 4 (author's user ID)
            author.first_name,            -- 5
            author.last_name,             -- 6
            images.created_at,            -- 7
            collaborator.id,              -- 8 (collaborator's user ID)
            collaborator.first_name,      -- 9
            collaborator.last_name        -- 10
        FROM images
        JOIN users AS author ON images.id = author.id
        LEFT JOIN users AS collaborator ON images.collaborator_id = collaborator.id
        LEFT JOIN (
            SELECT image_id, COUNT(*) AS like_count 
            FROM likes 
            GROUP BY image_id
        ) AS likes 
        ON images.image_id = likes.image_id
        WHERE images.id = %s OR images.collaborator_id = %s
        ORDER BY images.created_at DESC;
    """, (user_id, user_id))
    images = cur.fetchall()


    # Fetch comments on the user's posts
    cur.execute("""
        SELECT comments.comment_id, comments.image_id, users.first_name, 
               comments.comment_text, comments.created_at, 
               (SELECT COUNT(*) FROM comment_likes WHERE comment_likes.comment_id = comments.comment_id) AS like_count,
               comments.user_id
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.image_id IN (SELECT image_id FROM images WHERE id = %s OR collaborator_id = %s)
        ORDER BY comments.created_at ASC
    """, (user_id, user_id))
    comments = cur.fetchall()

    # Check friend status
    cur.execute("""
        SELECT 1 FROM friends 
        WHERE (user1_id = %s AND user2_id = %s)
           OR (user1_id = %s AND user2_id = %s);
    """, (current_user_id, user_id, user_id, current_user_id))
    is_friend = cur.fetchone() is not None

    # OUTGOING (You sent a request)
    cur.execute("""
        SELECT status FROM friend_requests
        WHERE sender_id = %s AND receiver_id = %s AND status = 'pending';
    """, (current_user.id, user_id))
    outgoing_request = cur.fetchone()


    # INCOMING (They sent a request)
    cur.execute("""
        SELECT request_id, status FROM friend_requests
        WHERE sender_id = %s AND receiver_id = %s AND status = 'pending';
    """, (user_id, current_user.id))
    incoming_request = cur.fetchone()

    # Fetch likes for each image
    likes_data = {}
    for image in images:
        image_id = image[0]
        cur.execute("""
            SELECT u.first_name || ' ' || u.last_name AS display_name, l.created_at
            FROM likes l
            JOIN users u ON l.user_id = u.id
            WHERE l.image_id = %s
            ORDER BY l.created_at DESC
        """, (image_id,))
        likes = cur.fetchall()
        likes_data[image_id] = likes

    # Likes for each comment
    comment_likes_data = {}
    for comment in comments:
        comment_id = comment[0]
        cur.execute("""
            SELECT u.first_name || ' ' || u.last_name AS display_name, cl.created_at
            FROM comment_likes cl
            JOIN users u ON cl.user_id = u.id
            WHERE cl.comment_id = %s
            ORDER BY cl.created_at DESC
        """, (comment_id,))
        comment_likes = cur.fetchall()
        comment_likes_data[comment_id] = comment_likes

                # Fetch notifications
    cur.execute("""
        SELECT users.first_name || ' ' || users.last_name AS display_name,
               notifications.action_type, notifications.image_id, notifications.created_at, notifications.actor_id
        FROM notifications
        JOIN users ON notifications.actor_id = users.id
        WHERE notifications.recipient_id = %s
        ORDER BY notifications.created_at DESC
    """, (current_user.id,))
    notifications = cur.fetchall()

    # Fetch friend requests
    cur.execute("""
        SELECT fr.request_id, fr.sender_id, u.first_name, u.last_name, fr.created_at
        FROM friend_requests fr
        JOIN users u ON fr.sender_id = u.id
        WHERE fr.receiver_id = %s AND fr.status = 'pending'
        ORDER BY fr.created_at DESC
    """, (current_user.id,))
    requests = cur.fetchall()

    # Fetch the saved image IDs for the user
    cur.execute("""
        SELECT image_id FROM saved_posts WHERE user_id = %s
    """, (user_id,))
    saved_image_ids = [row[0] for row in cur.fetchall()]
    
    cur.close()
    conn.close()

    # Determine whether to disable "Add Friend" button
    disable_add_friend = (
        is_friend or
        current_user_id == user_id or
        incoming_request is not None or # you cannot add if they already sent you a request
        outgoing_request is not None
    )

    location = ", ".join(filter(None, [city, state, country]))


    return render_template(
        "profile.html",
        current_page='profile',
        user=user,
        role=role,
        location=location,
        friend_count=friend_count,
        images=images,
        comments=comments,
        user_id=user_id,
        is_friend=is_friend,
        outgoing_request=outgoing_request,
        incoming_request=incoming_request,
        is_own_profile=(current_user_id == user_id),
        disable_add_friend=disable_add_friend,
        likes_data=likes_data,
        comment_likes_data=comment_likes_data,
        notifications=notifications,
        requests=requests,
        verified=current_user.verified,
        saved_image_ids=saved_image_ids
    )

@app.route('/send_request/<int:receiver_id>', methods=['POST'])
@login_required
def send_request(receiver_id):
    sender_id = current_user.id

    # ❌ Block if not verified
    if not current_user.verified:
        flash("You must verify your account before sending friend requests.")
        return redirect(url_for('profile', user_id=receiver_id))

    # Prevent sending a request to yourself
    if sender_id == receiver_id:
        flash("You cannot send a friend request to yourself.")
        return redirect(url_for('profile', user_id=receiver_id))

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()

    try:
        # ✅ Sort the IDs to match how the friends table stores relationships
        user1_id, user2_id = sorted((sender_id, receiver_id))

        # Prevent sending a request if already friends
        cur.execute("""
            SELECT * FROM friends
            WHERE user1_id = %s AND user2_id = %s;
        """, (user1_id, user2_id))
        already_friends = cur.fetchone()

        if already_friends:
            flash("You are already friends with this user.")
            return redirect(url_for('profile', user_id=receiver_id))

        # Prevent sending a duplicate pending request
        cur.execute("""
            SELECT * FROM friend_requests
            WHERE sender_id = %s AND receiver_id = %s AND status = 'pending';
        """, (sender_id, receiver_id))
        existing_request = cur.fetchone()

        if existing_request:
            flash("Friend request already sent.")
        else:
            # Handle rejected request and allow sending a new one
            cur.execute("""
                DELETE FROM friend_requests
                WHERE sender_id = %s AND receiver_id = %s AND status = 'rejected';
            """, (sender_id, receiver_id))
            conn.commit()

            # Insert new friend request
            cur.execute("""
                INSERT INTO friend_requests (sender_id, receiver_id, status, created_at)
                VALUES (%s, %s, 'pending', NOW());
            """, (sender_id, receiver_id))
            conn.commit()
            flash("Friend request sent.")
    except Exception as e:
        flash(f"An error occurred: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('profile', user_id=receiver_id))


@app.route('/unfriend/<int:other_user_id>', methods=['POST'])
@login_required
def unfriend(other_user_id):
    user_id = current_user.id

    if user_id == other_user_id:
        flash("You cannot unfriend yourself.")
        return redirect(url_for('profile', user_id=other_user_id))

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()

    try:
        # Delete from friends table
        user1_id, user2_id = sorted((user_id, other_user_id))
        cur.execute("""
            DELETE FROM friends
            WHERE user1_id = %s AND user2_id = %s;
        """, (user1_id, user2_id))

        # Delete any existing friend requests between these users (in either direction)
        cur.execute("""
            DELETE FROM friend_requests
            WHERE (sender_id = %s AND receiver_id = %s)
               OR (sender_id = %s AND receiver_id = %s);
        """, (user_id, other_user_id, other_user_id, user_id))

        conn.commit()

        flash("You have unfriended this user and cleared any past friend requests.")
    except Exception as e:
        flash(f"Error while unfriending: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('profile', user_id=other_user_id))



@app.route('/cancel_request/<int:receiver_id>', methods=['POST'])
@login_required
def cancel_request(receiver_id):
    sender_id = current_user.id

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()

    try:
        # ✅ Check if already friends
        user1_id, user2_id = sorted((sender_id, receiver_id))
        cur.execute("""
            SELECT * FROM friends
            WHERE user1_id = %s AND user2_id = %s;
        """, (user1_id, user2_id))
        already_friends = cur.fetchone()

        if already_friends:
            flash("You are already friends with this user.")
            return redirect(url_for('profile', user_id=receiver_id))

        # ❌ Only delete pending friend requests
        cur.execute("""
            DELETE FROM friend_requests
            WHERE sender_id = %s AND receiver_id = %s AND status = 'pending';
        """, (sender_id, receiver_id))
        conn.commit()

        flash("Friend request cancelled.")
    except Exception as e:
        flash(f"An error occurred: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('profile', user_id=receiver_id))


@app.route('/accept_request/<int:request_id>', methods=['POST'])
@login_required
def accept_request(request_id):
    if not current_user.verified:
        flash("Please verify your account before accepting friend requests.")
        return redirect('/requests')

    receiver_id = current_user.id
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()

    try:
        # Fetch sender from request
        cur.execute("""
            SELECT sender_id FROM friend_requests 
            WHERE request_id = %s AND receiver_id = %s AND status = 'pending';
        """, (request_id, receiver_id))
        row = cur.fetchone()

        if not row:
            flash("Friend request not found or already handled.")
            return redirect('/requests')

        sender_id = row[0]

        # Sort IDs for consistent friend record
        user1_id, user2_id = sorted((sender_id, receiver_id))

        # Check if they are already friends (prevent accidental double insert)
        cur.execute("""
            SELECT 1 FROM friends WHERE user1_id = %s AND user2_id = %s;
        """, (user1_id, user2_id))
        if cur.fetchone():
            flash("You are already friends.")
        else:
            # Update request status
            cur.execute("""
                UPDATE friend_requests SET status = 'accepted'
                WHERE request_id = %s;
            """, (request_id,))

            # Add to friends table
            cur.execute("""
                INSERT INTO friends (user1_id, user2_id) VALUES (%s, %s);
            """, (user1_id, user2_id))

            flash("Friend request accepted.")

        conn.commit()

    except Exception as e:
        conn.rollback()
        flash(f"An error occurred: {e}")
    finally:
        cur.close()
        conn.close()

    return redirect('/feed')


@app.route('/reject_request/<int:request_id>', methods=['POST'])
@login_required
def reject_request(request_id):
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()

    try:
        # Just delete the friend request with the given ID
        cur.execute("""
            DELETE FROM friend_requests
            WHERE id = %s;
        """, (request_id,))

        conn.commit()
        flash("Friend request rejected.")
    except Exception as e:
        flash(f"Error while rejecting request: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('profile', user_id=current_user.id))

@app.route('/pairup')
@login_required
def pairup():
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    # Fetch notifications
    cur.execute("""
        SELECT 
            users.first_name || ' ' || users.last_name AS display_name,
            notifications.action_type,
            notifications.image_id,
            notifications.created_at,
            notifications.actor_id
        FROM notifications
        JOIN users ON notifications.actor_id = users.id
        WHERE notifications.recipient_id = %s
        ORDER BY notifications.created_at DESC
    """, (current_user.id,))
    notifications = cur.fetchall()

    # Fetch friend requests
    cur.execute("""
        SELECT fr.request_id, fr.sender_id, u.first_name, u.last_name, fr.created_at
        FROM friend_requests fr
        JOIN users u ON fr.sender_id = u.id
        WHERE fr.receiver_id = %s AND fr.status = 'pending'
        ORDER BY fr.created_at DESC
    """, (current_user.id,))
    requests = cur.fetchall()


    # Fetch recent matches
    cur.execute("""
        SELECT u.id, u.first_name, u.last_name, rm.matched_at
        FROM recent_matches rm
        JOIN users u ON rm.matched_user_id = u.id
        WHERE rm.user_id = %s
        ORDER BY rm.matched_at DESC
    """, (current_user.id,))
    recent_matches = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("pairup.html", notifications=notifications, requests=requests, recent_matches=recent_matches)

@app.route('/match', methods=['POST'])
@login_required
def match():
    user_id = current_user.id

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    # Check last collab action
    cur.execute("""
        SELECT action_time FROM collab_actions
        WHERE user_id = %s
        ORDER BY action_time DESC
        LIMIT 1
    """, (user_id,))
    result = cur.fetchone()

    if result:
        last_action_time = result[0]

        # Ensure timezone-awareness (assuming stored in UTC)
        if last_action_time.tzinfo is None:
            last_action_time = last_action_time.replace(tzinfo=timezone.utc)

        now_utc = datetime.now(timezone.utc)

        if now_utc - last_action_time < timedelta(hours=24):
            cur.close()
            conn.close()
            return jsonify({'error': 'Access to /match is locked for 24 hours after collab check.'}), 403

    # Get all matched user IDs for current user
    cur.execute("""
    SELECT matched_user_id FROM recent_matches WHERE user_id = %s
    """, (user_id,))
    matched_ids = [row[0] for row in cur.fetchall()]

    exclude_ids = matched_ids + [user_id] or [-1]  # Ensure not empty

    # Fetch candidate users excluding matched ones and current user
    cur.execute("""
        SELECT id, skills, preferences, experience_level FROM users
        WHERE id NOT IN %s AND is_profile_complete = TRUE
    """, (tuple(exclude_ids),))
    rows = cur.fetchall()

    # Also fetch current user's data to include in DataFrame
    cur.execute("""
        SELECT id, skills, preferences, experience_level FROM users
        WHERE id = %s AND is_profile_complete = TRUE
    """, (user_id,))
    self_data = cur.fetchone()

    if self_data:
        rows.append(self_data)


    # Fetch notifications
    cur.execute("""
        SELECT
            users.first_name || ' ' || users.last_name AS display_name,
            notifications.action_type,
            notifications.image_id,
            notifications.created_at,
            notifications.actor_id
        FROM notifications
        JOIN users ON notifications.actor_id = users.id
        WHERE notifications.recipient_id = %s
        ORDER BY notifications.created_at DESC
    """, (user_id,))
    notifications = cur.fetchall()

    # Fetch friend requests
    cur.execute("""
        SELECT fr.request_id, fr.sender_id, u.first_name, u.last_name, fr.created_at
        FROM friend_requests fr
        JOIN users u ON fr.sender_id = u.id
        WHERE fr.receiver_id = %s AND fr.status = 'pending'
        ORDER BY fr.created_at DESC
    """, (user_id,))
    requests = cur.fetchall()

    # Prepare data for recommender
    users_data = []
    for row in rows:
        uid, skills, prefs, level = row
        row_data = {'user': uid}
        for cat in ["Typography", "Branding", "Advertising", "Graphic Design", "Illustration", 
                    "3D Design", "Animation", "Packaging", "Infographics", "UI/UX Design"]:
            row_data[f"{cat}_skill"] = int(cat in (skills or []))
            row_data[f"{cat}_pref"] = int(cat in (prefs or []))
        row_data["Experience_Level"] = level or 0
        users_data.append(row_data)

    df = pd.DataFrame(users_data)

    if user_id not in df["user"].values:
        cur.close()
        conn.close()
        return "Please complete your profile to get recommendations."

    # Recommender logic
    target_index = df[df['user'] == user_id].index[0]
    similar_users_df = get_similar_users(target_index, df)

    if similar_users_df.empty:
        cur.close()
        conn.close()
        return render_template("match.html", users=[])

    # Get recommended user info
    user_ids = similar_users_df['user'].tolist()
    cur.execute("SELECT id, first_name, last_name, role FROM users WHERE id = ANY(%s)", (user_ids,))
    name_rows = cur.fetchall()

    cur.close()
    conn.close()

    name_map = {
        row[0]: {
            "id": row[0],
            "first_name": row[1],
            "last_name": row[2],
            "role": row[3]
        }
        for row in name_rows
    }

    users_list = []
    for user in similar_users_df.to_dict(orient='records'):
        details = name_map.get(user["user"], {})
        user["id"] = details.get("id", user["user"])  # Add this line to ensure 'id' is set
        user["first_name"] = details.get("first_name", "Unknown")
        user["last_name"] = details.get("last_name", "")
        user["role"] = details.get("role", "")
        users_list.append(user)

    return render_template("match.html", current_page='match', user=users_list[0], notifications=notifications, requests=requests)

@app.route('/api/get-countries')
def get_countries():
    return jsonify(app.config['COUNTRIES'])

@app.route('/api/get-states')
def get_states():
    return jsonify(app.config['STATES'])

@app.route('/api/get-cities')
def get_cities():
    country_code = request.args.get('country')
    state_code = request.args.get('state')

    if not country_code or not state_code:
        return jsonify([])

    filtered = [
        city for city in app.config['CITIES']
        if city['country_code'] == country_code and city['state_code'] == state_code
    ]
    return jsonify(filtered)


@app.route('/notify/collab_check', methods=['POST'])
@login_required
def notify_collab_check():
    data = request.get_json()
    try:
        recipient_id = int(data.get('recipient_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid recipient_id'}), 400

    actor_id = current_user.id
    conn = None

    try:
        conn = psycopg2.connect(
            host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
            dbname="ocularis_db", 
            user="ocularis_db_user", 
            password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
            port=5432
        )
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO notifications (recipient_id, actor_id, action_type)
                    VALUES (%s, %s, 'collab_check')
                """, (recipient_id, actor_id))

                cur.execute("""
                    INSERT INTO collab_actions (user_id) VALUES (%s)
                """, (actor_id,))

                cur.execute("""
                    INSERT INTO recent_matches (user_id, matched_user_id)
                    VALUES (%s, %s), (%s, %s)
                """, (actor_id, recipient_id, recipient_id, actor_id))

                
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

    return jsonify({'message': 'Notification sent to collaborator'}), 201



def get_random_users():
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )

    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, first_name, last_name, city, role
                FROM users
                WHERE is_profile_complete = TRUE
                AND id != %s
                AND id NOT IN (
                    SELECT recipient_id FROM notifications 
                    WHERE actor_id = %s AND action_type = 'collab_check'
                    UNION
                    SELECT actor_id FROM notifications 
                    WHERE recipient_id = %s AND action_type = 'collab_check'
                )
                ORDER BY RANDOM()
                LIMIT 20;
            """, (current_user.id, current_user.id, current_user.id))

            users = cur.fetchall()

    return users


@app.route('/browse', methods=['POST'])
@login_required
def browse_users():
    user_id = current_user.id

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )

    cur = conn.cursor()

    # Fetch notifications
    cur.execute("""
        SELECT 
            users.first_name || ' ' || users.last_name AS display_name,
            notifications.action_type,
            notifications.image_id,
            notifications.created_at,
            notifications.actor_id
        FROM notifications
        JOIN users ON notifications.actor_id = users.id
        WHERE notifications.recipient_id = %s
        ORDER BY notifications.created_at DESC
    """, (current_user.id,))
    notifications = cur.fetchall()

    # Fetch friend requests
    cur.execute("""
        SELECT fr.request_id, fr.sender_id, u.first_name, u.last_name, fr.created_at
        FROM friend_requests fr
        JOIN users u ON fr.sender_id = u.id
        WHERE fr.receiver_id = %s AND fr.status = 'pending'
        ORDER BY fr.created_at DESC
    """, (current_user.id,))
    requests = cur.fetchall()

    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # 1. 24-hour collab action block check
            cur.execute("""
                SELECT action_time FROM collab_actions
                WHERE user_id = %s
                ORDER BY action_time DESC
                LIMIT 1
            """, (user_id,))
            result = cur.fetchone()

            if result:
                last_action_time = result["action_time"]
                if last_action_time.tzinfo is None:
                    last_action_time = last_action_time.replace(tzinfo=timezone.utc)

                now_utc = datetime.now(timezone.utc)
                if now_utc - last_action_time < timedelta(hours=24):
                    return jsonify({'error': 'Access to /browse is locked for 24 hours after collab check.'}), 403

    # 4. Get filtered random users
    users = get_random_users()

    return render_template(
        'browse.html',
        users=users,
        notifications=notifications,
        requests=requests
    )


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user_id = current_user.id
    if not user_id:
        return redirect(url_for('login'))

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    if request.method == 'POST':
        # Get form data
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        role = request.form.get('role')
        country = request.form.get('country')   # should be country code (iso2)
        state = request.form.get('state')       # state code
        city = request.form.get('city')         # city code
        experience_level = request.form.get('experience_level')

        skills_list = request.form.getlist('skills[]')
        preferences_list = request.form.getlist('preferences[]')

        facebook = request.form.get('facebook')
        instagram = request.form.get('instagram')
        x = request.form.get('x')
        linkedin = request.form.get('linkedin')
        telegram = request.form.get('telegram')

        profile_pic = request.files.get('profile_pic')
        if profile_pic and profile_pic.filename != '':
            filename = f"user_{user_id}_profile.{profile_pic.filename.rsplit('.', 1)[1]}"
            filepath = os.path.join('static/uploads/profile_pics', filename)
            profile_pic.save(filepath)
            # Update profile_pic path in DB
            cur.execute("UPDATE users SET profile_pic = %s WHERE id = %s", (filepath, user_id))

        # Update user data (assuming skills, preferences stored as arrays in DB)
        cur.execute("""
            UPDATE users SET
                first_name = %s,
                last_name = %s,
                role = %s,
                country = %s,
                state = %s,
                city = %s,
                skills = %s,
                preferences = %s,
                experience_level = %s,
                facebook = %s,
                instagram = %s,
                x = %s,
                linkedin = %s,
                telegram = %s
            WHERE id = %s
        """, (
            first_name,
            last_name,
            role,
            country,
            state,
            city,
            skills_list,
            preferences_list,
            experience_level,
            facebook,
            instagram,
            x,
            linkedin,
            telegram,
            user_id
        ))

        conn.commit()
        cur.close()
        conn.close()

        flash("Settings updated successfully.", "success")
        return redirect(url_for('settings'))

    else:
        # GET: fetch user info + countries list
        cur.execute("""
            SELECT first_name, last_name, role, country, state, city, skills, preferences,
                   experience_level, facebook, instagram, x, linkedin, telegram
            FROM users WHERE id = %s
        """, (user_id,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            user_dict = {
                'first_name': user[0],
                'last_name': user[1],
                'role': user[2],
                'country': user[3],
                'state': user[4],
                'city': user[5],
                'skills': ', '.join(user[6]) if user[6] else '',
                'preferences': ', '.join(user[7]) if user[7] else '',
                'experience_level': user[8],
                'facebook': user[9],
                'instagram': user[10],
                'x': user[11],
                'linkedin': user[12],
                'telegram': user[13]
            }

            countries = app.config['COUNTRIES']  # List of countries for dropdown

            categories = [
                "Typography", "Branding", "Advertising", "Graphic Design", "Illustration",
                "3D Design", "Animation", "Packaging", "Infographics", "UI/UX Design"
            ]

            experience_levels = [
                (1, "Beginner"),
                (2, "Intermediate"),
                (3, "Advanced"),
                (4, "Expert")
            ]

            return render_template('settings.html', user=user_dict, countries=countries, categories=categories, experience_levels=experience_levels)
        else:
            flash("User not found.", "danger")
            return redirect(url_for('login'))


def save_post(user_id, image_id, conn):
    with conn.cursor() as cur:
        try:
            cur.execute("""
                INSERT INTO saved_posts (user_id, image_id)
                VALUES (%s, %s)
                ON CONFLICT (user_id, image_id) DO NOTHING
            """, (user_id, image_id))
            conn.commit()
            return {"success": True, "message": "Post saved successfully."}
        except Exception as e:
            conn.rollback()
            return {"success": False, "message": str(e)}

@app.route('/saved')
@login_required
def saved():
    user_id = current_user.id
    if not user_id:
        return redirect(url_for('login'))

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    # 1. Fetch saved posts
    cur.execute("""
        SELECT 
            images.image_id,                            -- image[0]
            images.image_url,                           -- image[1]
            images.caption,                             -- image[2]
            COUNT(likes.image_id) AS like_count,        -- image[3] ← updated
            author.id AS author_id,                     -- image[4]
            author.first_name,                          -- image[5]
            author.last_name,                           -- image[6]
            images.created_at,                          -- image[7] (for date formatting)
            collaborator.id AS collaborator_id,         -- image[8]
            collaborator.first_name,                    -- image[9]
            collaborator.last_name                      -- image[10]
        FROM saved_posts
        JOIN images ON saved_posts.image_id = images.image_id
        JOIN users AS author ON images.id = author.id
        LEFT JOIN users AS collaborator ON images.collaborator_id = collaborator.id
        LEFT JOIN likes ON images.image_id = likes.image_id
        WHERE saved_posts.user_id = %s
        GROUP BY 
            images.image_id, images.image_url, images.caption, images.created_at,
            author.id, author.first_name, author.last_name,
            collaborator.id, collaborator.first_name, collaborator.last_name,
            saved_posts.saved_at
        ORDER BY saved_posts.saved_at DESC;
    """, (user_id,))
    saved_posts = cur.fetchall()

    # Initialize containers
    all_comments = {}
    likes_data = {}
    comment_likes_data = {}

    for post in saved_posts:
        image_id = post[0]  # images.image_id

        # 2. Fetch comments per image
        cur.execute("""
            SELECT comments.comment_id, comments.image_id, 
                   users.first_name || ' ' || users.last_name AS display_name, 
                   comments.comment_text, comments.created_at,
                   COALESCE(like_count, 0) AS like_count, comments.user_id
            FROM comments
            JOIN users ON comments.user_id = users.id
            LEFT JOIN (
                SELECT comment_id, COUNT(*) AS like_count
                FROM comment_likes
                GROUP BY comment_id
            ) AS cl ON comments.comment_id = cl.comment_id
            WHERE comments.image_id = %s
            ORDER BY comments.created_at ASC
        """, (image_id,))
        comments = cur.fetchall()
        all_comments[image_id] = comments

        # 3. Likes per image
        cur.execute("""
            SELECT u.first_name || ' ' || u.last_name AS display_name, l.created_at
            FROM likes l
            JOIN users u ON l.user_id = u.id
            WHERE l.image_id = %s
            ORDER BY l.created_at DESC
        """, (image_id,))
        likes_data[image_id] = cur.fetchall()

        # 4. Likes per comment
        for comment in comments:
            comment_id = comment[0]
            cur.execute("""
                SELECT u.first_name || ' ' || u.last_name AS display_name, cl.created_at
                FROM comment_likes cl
                JOIN users u ON cl.user_id = u.id
                WHERE cl.comment_id = %s
                ORDER BY cl.created_at DESC
            """, (comment_id,))
            comment_likes_data[comment_id] = cur.fetchall()

    # 5. Notifications
    cur.execute("""
        SELECT users.first_name || ' ' || users.last_name AS display_name,
               notifications.action_type, notifications.image_id, notifications.created_at, notifications.actor_id
        FROM notifications
        JOIN users ON notifications.actor_id = users.id
        WHERE notifications.recipient_id = %s
        ORDER BY notifications.created_at DESC
    """, (user_id,))
    notifications = cur.fetchall()

    # 6. Friend requests
    cur.execute("""
        SELECT fr.request_id, fr.sender_id, u.first_name, u.last_name, fr.created_at
        FROM friend_requests fr
        JOIN users u ON fr.sender_id = u.id
        WHERE fr.receiver_id = %s AND fr.status = 'pending'
        ORDER BY fr.created_at DESC
    """, (user_id,))
    requests = cur.fetchall()

    cur.close()
    conn.close()

    return render_template('saved.html',
        saved_posts=saved_posts,
        comments=all_comments,
        likes_data=likes_data,
        comment_likes_data=comment_likes_data,
        notifications=notifications,
        requests=requests,
        verified=current_user.verified)


@app.route('/save/<int:image_id>', methods=['POST'])
@login_required
def save_image(image_id):
    user_id = current_user.id

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )

    save_post(user_id, image_id, conn)
    conn.close()

    return redirect(url_for('saved'))


@app.route('/unsave/<int:image_id>', methods=['POST'])
@login_required
def unsave_image(image_id):
    user_id = current_user.id

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    cur.execute("""
        DELETE FROM saved_posts 
        WHERE user_id = %s AND image_id = %s
    """, (user_id, image_id))

    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for('saved'))


if __name__ == '__main__':
    app.run(debug=True)