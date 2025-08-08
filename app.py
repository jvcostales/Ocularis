from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, flash, jsonify, abort, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import psycopg2
from werkzeug.utils import secure_filename
import os
import smtplib
import secrets
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from recommender import get_similar_users
from datetime import datetime, timedelta, timezone
import pandas as pd
import json
from psycopg2.extras import RealDictCursor
import uuid
from urllib.parse import urlparse, urljoin
import pytz

app = Flask(__name__)
app.secret_key = 'v$2nG#8mKqT3@z!bW7e^d6rY*9xU&j!P'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
    profile_pic VARCHAR(255),
    cover_photo VARCHAR(255),
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
    FOREIGN KEY (collaborator_id) REFERENCES users(id) ON DELETE SET NULL
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

cur.execute("""
CREATE TABLE IF NOT EXISTS hidden_posts (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    image_id INTEGER NOT NULL REFERENCES images(image_id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, image_id)
);
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS reports (
    id SERIAL PRIMARY KEY,
    image_id INT NOT NULL,
    user_id INT NOT NULL,
    reasons TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (image_id) REFERENCES images(image_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))
    else:
        return redirect(url_for('login'))

def send_verification_email(recipient_email, token):
    confirmation_link = f"https://ocularis.onrender.com/confirm-email/{token}"
    subject = "Verify your email for Ocularis"

    text_body = f"Hi there!\nPlease verify your email by clicking this link:\n{confirmation_link}"

    html_body = f"""
    <html>
    <body style="font-family: 'Schibsted Grotesk', sans-serif; font-size: 1rem; color: #1a1a1a; text-align: center; background-color: #ffffff; padding: 40px;">

        <div style="font-size: 1rem; font-weight: 600; margin-bottom: 12px;">
            Verify Your Email Address
        </div>

        <div style="margin-bottom: 24px;">
            Click the button below to verify your email for Ocularis.
        </div>

        <a href="{confirmation_link}" 
        style="display: inline-block;
                font-size: 1rem;
                font-family: 'Schibsted Grotesk', sans-serif;
                padding: 12px 24px;
                box-sizing: border-box;
                border: none;
                background-color: #1C46F5;
                border-radius: 10px;
                cursor: pointer;
                color: #f6f6f6;
                text-align: center;
                text-decoration: none;
                font-weight: bold;
                margin-bottom: 24px;">
            Verify Email
        </a>

        <div style="margin-top: 24px; font-size: 1rem; color: #a6a6a6;">
            If you did not sign up, please ignore this message.
        </div>

        <div style="margin-top: 40px; font-size: 0.75rem; color: #a6a6a6;">
            © 2025 Jady Nicole Costales. All rights reserved.
        </div>

    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = "ocularis.research@gmail.com"
    msg["To"] = recipient_email

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login("ocularis.research@gmail.com", "dpjv lgbn cdcw osop")  # Use env var in production
            server.send_message(msg)
    except Exception as e:
        app.logger.error(f"Failed to send email: {e}")
        
@app.route('/confirm-email/<token>')
def confirm_email(token):
    return render_template('confirm_verification.html', token=token)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        raw_password = request.form.get('password')

        if not first_name or not last_name or not email or not raw_password:
            flash("All fields are required.")
            return redirect(url_for('signup'))

        if len(raw_password) < 6:
            flash("Password must be at least 6 characters long.")
            return redirect(url_for('signup'))

        password = generate_password_hash(raw_password)
        token = secrets.token_urlsafe(32)
        default_profile_pic = "pfp.jpg"
        default_cover_photo = "default_cover.png"

        try:
            conn = psycopg2.connect(
                host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
                dbname="ocularis_db",
                user="ocularis_db_user",
                password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
                port=5432
            )
            cur = conn.cursor()

            cur.execute("SELECT 1 FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                flash("Email already exists.")
                return redirect(url_for('signup'))

            cur.execute("""
                INSERT INTO users (first_name, last_name, email, password, verification_token, verified, profile_pic, cover_photo)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (first_name, last_name, email, password, token, False, default_profile_pic, default_cover_photo))

            user_id = cur.fetchone()[0]
            conn.commit()

            send_verification_email(email, token)
            flash("Check your email to verify your account.")
            return redirect(url_for('login'))  # Redirect to login after successful signup
        except Exception as e:
            app.logger.error(f"Signup error: {e}")
            flash("An error occurred. Please try again.")
            return redirect(url_for('signup'))
        finally:
            if 'cur' in locals():
                cur.close()
            if 'conn' in locals():
                conn.close()

    return render_template('signup.html')

@app.route('/finalize-verification/<token>', methods=['POST'])
def finalize_verification(token):
    try:
        conn = psycopg2.connect(
            host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
            dbname="ocularis_db",
            user="ocularis_db_user",
            password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
            port=5432
        )
        cur = conn.cursor()

        cur.execute("SELECT id, verified FROM users WHERE verification_token = %s", (token,))
        user = cur.fetchone()

        if not user:
            return "Invalid or expired token."
        if user[1]:
            return "Account already verified."

        cur.execute("""
            UPDATE users
            SET verified = TRUE, verification_token = NULL
            WHERE id = %s
        """, (user[0],))
        conn.commit()
        return "Email verified successfully! You can now log in."
    except Exception as e:
        app.logger.error(f"Verification error: {e}")
        return "An error occurred during verification."
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (test_url.scheme in ('http', 'https') and
            ref_url.netloc == test_url.netloc)

def is_safe_url(target):
    # Helper to prevent open redirects
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('feed'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = 'remember' in request.form

        try:
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

            if user and check_password_hash(user[4], password):
                user_obj = User(id=user[0], first_name=user[1], last_name=user[2], email=user[3], password=user[4])
                login_user(user_obj, remember=remember)

                next_page = request.args.get('next')
                if next_page and is_safe_url(next_page):
                    return redirect(next_page)
                return redirect(url_for('feed'))
            else:
                flash("Invalid email or password.")
                return redirect(url_for('login'))

        except Exception as e:
            flash("An error occurred. Please try again.")
            return redirect(url_for('login'))

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
    sender_email = "ocularis.research@gmail.com"
    sender_password = "dpjv lgbn cdcw osop"

    msg = MIMEText(f'Click the link to reset your password on Ocularis: {reset_link}')
    msg['Subject'] = 'Reset Your Password'
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
        collaborator_id = request.form.get('collaborator')

        if file.filename == '':
            return 'No selected file'

        if file and allowed_file(file.filename):
            # Get original extension and generate unique filename
            ext = os.path.splitext(secure_filename(file.filename))[1]
            unique_filename = f"{uuid.uuid4().hex}{ext}"
            file_path = os.path.join('/var/data', unique_filename)
            file.save(file_path)

            image_url = f"https://ocularis.onrender.com/images/{unique_filename}"

            conn = psycopg2.connect(
                host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
                dbname="ocularis_db", 
                user="ocularis_db_user", 
                password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
                port=5432
            )
            cur = conn.cursor()

            # Insert image with or without collaborator
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

            # Insert tags
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
        query = request.args.get('query', '').strip()
        like_query = f"%{query}%"
        cur.execute("""
            SELECT 
                images.image_id,
                images.image_url,
                images.caption,
                COALESCE(like_count, 0),
                images.id,
                author.first_name,
                author.last_name,
                images.created_at,
                collaborator.id,
                collaborator.first_name,
                collaborator.last_name,
                author.profile_pic,
                collaborator.profile_pic,
                EXISTS (
                    SELECT 1 FROM likes 
                    WHERE user_id = %s AND image_id = images.image_id
                ) AS is_liked
            FROM images
            JOIN users AS author ON images.id = author.id
            LEFT JOIN users AS collaborator ON images.collaborator_id = collaborator.id
            LEFT JOIN (
                SELECT image_id, COUNT(*) AS like_count 
                FROM likes 
                GROUP BY image_id
            ) AS likes ON images.image_id = likes.image_id
            LEFT JOIN image_tags ON images.image_id = image_tags.image_id
            LEFT JOIN hidden_posts hp ON images.image_id = hp.image_id AND hp.user_id = %s
            WHERE hp.user_id IS NULL
            AND (
                    images.caption ILIKE %s OR
                    image_tags.tag ILIKE %s OR
                    (author.first_name || ' ' || author.last_name) ILIKE %s OR
                    (collaborator.first_name || ' ' || collaborator.last_name) ILIKE %s
                )
            ORDER BY images.created_at DESC
        """, (user_id, user_id, like_query, like_query, like_query, like_query))
        images = cur.fetchall()

        # Fetch comments with commenter profile picture
        cur.execute("""
            SELECT 
                comments.comment_id,                   -- 0
                comments.image_id,                     -- 1
                users.first_name || ' ' || users.last_name AS display_name,  -- 2
                comments.comment_text,                 -- 3
                comments.created_at,                   -- 4
                COALESCE(like_count, 0) AS like_count, -- 5
                comments.user_id,                      -- 6
                users.profile_pic,                     -- 7
                EXISTS (                               -- 8 ✅ NEW: whether current user liked this comment
                    SELECT 1 FROM comment_likes 
                    WHERE comment_likes.comment_id = comments.comment_id 
                    AND comment_likes.user_id = %s
                ) AS is_liked
            FROM comments
            JOIN users ON comments.user_id = users.id
            LEFT JOIN (
                SELECT comment_id, COUNT(*) AS like_count
                FROM comment_likes
                GROUP BY comment_id
            ) AS cl ON comments.comment_id = cl.comment_id
            ORDER BY comments.created_at ASC
        """, (user_id,))
        comments = cur.fetchall()


        # First, fetch user's notification preferences
        cur.execute("""
            SELECT notify_likes, notify_comments, notify_requests
            FROM users
            WHERE id = %s
        """, (current_user.id,))
        prefs = cur.fetchone()
        notify_likes, notify_comments, notify_requests = prefs

        # Build base query
        query = """
            SELECT 
                users.first_name || ' ' || users.last_name AS display_name,
                notifications.action_type,
                notifications.image_id,
                notifications.created_at,
                notifications.actor_id,
                users.profile_pic,
                notifications.notification_id
            FROM notifications
            JOIN users ON notifications.actor_id = users.id
            WHERE notifications.recipient_id = %s
        """

        params = [current_user.id]

        # Add filtering logic based on preferences
        disabled_types = []
        if not notify_likes:
            disabled_types.append('like')
        if not notify_comments:
            disabled_types.append('comment')
        if not notify_requests:
            disabled_types.append('request')

        if disabled_types:
            query += " AND notifications.action_type NOT IN %s"
            params.append(tuple(disabled_types))

        query += " ORDER BY notifications.created_at DESC"

        # Execute the final query
        cur.execute(query, params)
        notifications = cur.fetchall()
        
        # Gather unique actor_ids
        actor_ids = list(set([n[4] for n in notifications]))

            # Prepare dictionary to hold actor_id → user profile details
        actor_details = {}

            # Fetch full details for each actor_id
        for actor_id in actor_ids:
            cur.execute("""
                SELECT first_name, last_name, role, city, state, country, 
                    profile_pic, cover_photo, skills, preferences, experience_level,
                    facebook, instagram, x, linkedin, telegram, email
                FROM users WHERE id = %s
            """, (actor_id,))
            user = cur.fetchone()

            if user:
                countries = current_app.config['COUNTRIES']
                states = current_app.config['STATES']

                # Get raw codes
                city = user[3]
                state_code = user[4]
                country_code = user[5]

                # Look up readable names
                iso_to_country = {c["iso2"]: c["name"] for c in countries}
                readable_country = iso_to_country.get(country_code, country_code)

                # Filter states by selected country
                filtered_states = [s for s in states if s["country_code"] == country_code]
                state_code_to_name = {s["state_code"]: s["name"] for s in filtered_states}
                readable_state = state_code_to_name.get(state_code, state_code)

                # Display-friendly location string
                location_display = ", ".join(filter(None, [city, readable_state, readable_country]))

                actor_details[actor_id] = {
                    "user_id": actor_id,
                    "full_name": f"{user[0]} {user[1]}",
                    "role": user[2],
                    "city": city,
                    "state": state_code,
                    "country": country_code,
                    "location_display": location_display,  # ✅ new key
                    "profile_pic": user[6],
                    "cover_photo": user[7],
                    "skills": user[8],
                    "preferences": user[9],
                    "experience_level": user[10],
                    "facebook": user[11],
                    "instagram": user[12],
                    "x": user[13],
                    "linkedin": user[14],
                    "telegram": user[15],
                    "email": user[16]
                }

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

        # ✅ Always define profile_pic_url before it's used anywhere
        cur.execute("SELECT profile_pic FROM users WHERE id = %s", (current_user.id,))
        result = cur.fetchone()

        if result and result[0] and result[0] != 'pfp.jpg':
            profile_pic_url = url_for('profile_pics', filename=result[0])
        else:
            profile_pic_url = url_for('static', filename='pfp.jpg')

        # ✅ Then handle likes for each comment
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
        user=current_user,
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
        saved_image_ids=saved_image_ids,
        profile_pic_url=profile_pic_url,
        actor_details=actor_details
    )

@app.route('/post/<int:image_id>')
def view_post(image_id):
    
    user_id = current_user.id

    if not current_user.is_authenticated:
        return redirect(url_for('login', next=request.url))
    
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()
    
    cur.execute("""
        SELECT first_name, last_name, role, city, state, country, profile_pic 
        FROM users 
        WHERE id = %s
    """, (current_user.id,))
    user = cur.fetchone()

    try:
        # Fetch a single image by image_id
        cur.execute("""
            SELECT images.image_id, images.image_url, images.caption,
                COALESCE(like_count, 0),
                images.id AS author_id,
                author.first_name, author.last_name,
                images.created_at,
                collaborator.id AS collaborator_id,
                collaborator.first_name, collaborator.last_name,
                author.profile_pic,
                collaborator.profile_pic,
                EXISTS (
                    SELECT 1 FROM likes 
                    WHERE user_id = %s AND image_id = images.image_id
                ) AS is_liked
            FROM images 
            JOIN users AS author ON images.id = author.id
            LEFT JOIN (
                SELECT image_id, COUNT(*) AS like_count 
                FROM likes 
                GROUP BY image_id
            ) AS likes ON images.image_id = likes.image_id
            LEFT JOIN users AS collaborator ON images.collaborator_id = collaborator.id
            WHERE images.image_id = %s
        """, (current_user.id, image_id))

        image = cur.fetchone()

        if not image:
            abort(404)

        # Fetch comments for that image with like status for the current user
        cur.execute("""
            SELECT 
                comments.comment_id,                     -- 0
                comments.image_id,                       -- 1
                users.first_name || ' ' || users.last_name AS display_name,  -- 2
                comments.comment_text,                   -- 3
                comments.created_at,                     -- 4
                COALESCE(like_count, 0) AS like_count,   -- 5
                comments.user_id,                        -- 6
                users.profile_pic,                       -- 7
                EXISTS (                                 -- 8 ✅ NEW: whether current user liked the comment
                    SELECT 1 FROM comment_likes 
                    WHERE comment_likes.comment_id = comments.comment_id 
                    AND comment_likes.user_id = %s
                ) AS is_liked
            FROM comments
            JOIN users ON comments.user_id = users.id
            LEFT JOIN (
                SELECT comment_id, COUNT(*) AS like_count
                FROM comment_likes
                GROUP BY comment_id
            ) AS cl ON comments.comment_id = cl.comment_id
            WHERE comments.image_id = %s
            ORDER BY comments.created_at ASC
        """, (user_id, image_id))
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
            SELECT                 
                users.first_name || ' ' || users.last_name AS display_name,
                notifications.action_type,
                notifications.image_id,
                notifications.created_at,
                notifications.actor_id,
                users.profile_pic,
                notifications.notification_id
            FROM notifications
            JOIN users ON notifications.actor_id = users.id
            WHERE notifications.recipient_id = %s
            ORDER BY notifications.created_at DESC
        """, (current_user.id,))
        notifications = cur.fetchall()
        
                # Gather unique actor_ids
        actor_ids = list(set([n[4] for n in notifications]))

            # Prepare dictionary to hold actor_id → user profile details
        actor_details = {}

            # Fetch full details for each actor_id
        for actor_id in actor_ids:
            cur.execute("""
                SELECT first_name, last_name, role, city, state, country, 
                    profile_pic, cover_photo, skills, preferences, experience_level,
                    facebook, instagram, x, linkedin, telegram, email
                FROM users WHERE id = %s
            """, (actor_id,))
            user = cur.fetchone()

            if user:
                countries = current_app.config['COUNTRIES']
                states = current_app.config['STATES']

                # Get raw codes
                city = user[3]
                state_code = user[4]
                country_code = user[5]

                # Look up readable names
                iso_to_country = {c["iso2"]: c["name"] for c in countries}
                readable_country = iso_to_country.get(country_code, country_code)

                # Filter states by selected country
                filtered_states = [s for s in states if s["country_code"] == country_code]
                state_code_to_name = {s["state_code"]: s["name"] for s in filtered_states}
                readable_state = state_code_to_name.get(state_code, state_code)

                # Display-friendly location string
                location_display = ", ".join(filter(None, [city, readable_state, readable_country]))

                actor_details[actor_id] = {
                    "user_id": actor_id,
                    "full_name": f"{user[0]} {user[1]}",
                    "role": user[2],
                    "city": city,
                    "state": state_code,
                    "country": country_code,
                    "location_display": location_display,  # ✅ new key
                    "profile_pic": user[6],
                    "cover_photo": user[7],
                    "skills": user[8],
                    "preferences": user[9],
                    "experience_level": user[10],
                    "facebook": user[11],
                    "instagram": user[12],
                    "x": user[13],
                    "linkedin": user[14],
                    "telegram": user[15],
                    "email": user[16]
                }

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
        """, (current_user.id,))
        saved_image_ids = [row[0] for row in cur.fetchall()]

        # New query to get current user's profile_pic
        cur.execute("SELECT profile_pic FROM users WHERE id = %s", (current_user.id,))
        result = cur.fetchone()

        if result and result[0] and result[0] != 'pfp.jpg':
            profile_pic_url = url_for('profile_pics', filename=result[0])
        else:
            profile_pic_url = url_for('static', filename='pfp.jpg')

    
    finally:
        cur.close()
        conn.close()

    return render_template(
        'post.html',
        user=user,
        image=image,
        comments=comments,
        likes_data=likes_data,
        comment_likes_data=comment_likes_data,
        notifications=notifications,
        requests=requests,
        verified=current_user.verified,
        saved_image_ids=saved_image_ids,
        profile_pic_url=profile_pic_url,
        actor_details=actor_details
    )

@app.route('/hide_post/<int:image_id>', methods=['POST'])
@login_required
def hide_post(image_id):
    user_id = current_user.id
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()
    try:
        # Insert or ignore if already hidden
        cur.execute("""
            INSERT INTO hidden_posts (user_id, image_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
        """, (user_id, image_id))
        conn.commit()
        return jsonify({'status': 'success', 'message': 'Post hidden'})
    except Exception as e:
        conn.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

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

            # Get the image owner's ID and their like notification preference
            cur.execute("""
                SELECT users.id, users.notify_likes
                FROM images
                JOIN users ON images.id = users.id
                WHERE images.image_id = %s
            """, (image_id,))
            owner_info = cur.fetchone()

            if owner_info:
                owner_id, notify_likes = owner_info

                # Only create notification if the liker is not the owner AND likes are enabled
                if owner_id != current_user.id and notify_likes:
                    cur.execute("""
                        INSERT INTO notifications (recipient_id, actor_id, image_id, action_type)
                        VALUES (%s, %s, %s, 'like')
                    """, (owner_id, current_user.id, image_id))

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
    current_user_id = current_user.id

    try:
        # Get likers and include profile_pic
        cur.execute("""
            SELECT u.id, u.first_name || ' ' || u.last_name AS display_name, 
                   l.created_at, u.verified, u.profile_pic
            FROM likes l
            JOIN users u ON l.user_id = u.id
            WHERE l.image_id = %s
            ORDER BY l.created_at DESC
        """, (image_id,))
        likes = cur.fetchall()

        likers = []
        for liker_id, display_name, created_at, verified, profile_pic in likes:
            if liker_id == current_user_id:
                relationship = 'self'
                request_id = None
            else:
                # Check if they are already friends
                cur.execute("""
                    SELECT 1 FROM friends 
                    WHERE (user1_id = %s AND user2_id = %s)
                       OR (user1_id = %s AND user2_id = %s);
                """, (current_user_id, liker_id, liker_id, current_user_id))
                is_friend = cur.fetchone() is not None

                if is_friend:
                    relationship = 'friends'
                    request_id = None
                else:
                    # Outgoing request
                    cur.execute("""
                        SELECT status FROM friend_requests
                        WHERE sender_id = %s AND receiver_id = %s;
                    """, (current_user_id, liker_id))
                    outgoing = cur.fetchone()

                    if outgoing:
                        status = outgoing[0]
                        if status == 'pending':
                            relationship = 'outgoing_pending'
                        elif status == 'rejected':
                            relationship = 'outgoing_rejected'
                        else:
                            relationship = 'not_friends'
                        request_id = None
                    else:
                        # Incoming request
                        cur.execute("""
                            SELECT request_id FROM friend_requests
                            WHERE sender_id = %s AND receiver_id = %s AND status = 'pending';
                        """, (liker_id, current_user_id))
                        incoming = cur.fetchone()

                        if incoming:
                            relationship = 'incoming_pending'
                            request_id = incoming[0]
                        else:
                            relationship = 'not_friends'
                            request_id = None

            likers.append({
                'id': liker_id,
                'name': display_name,
                'timestamp': created_at.isoformat(),
                'relationship': relationship,
                'request_id': request_id,
                'verified': verified,
                'profile_pic': profile_pic
            })

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

    if not comment_text or not comment_text.strip():
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
        # Insert the comment and get its id and creation time
        cur.execute(
            "INSERT INTO comments (user_id, image_id, comment_text) VALUES (%s, %s, %s) RETURNING comment_id, created_at",
            (current_user.id, image_id, comment_text)
        )
        comment_id, created_at = cur.fetchone()

        # Get the image owner and their comment notification setting
        cur.execute("""
            SELECT users.id, users.notify_comments
            FROM images
            JOIN users ON images.id = users.id
            WHERE images.image_id = %s
        """, (image_id,))
        owner_info = cur.fetchone()

        if owner_info:
            owner_id, notify_comments = owner_info

            # Create notification only if commenter is not the owner AND notify_comments is enabled
            if owner_id != current_user.id and notify_comments:
                cur.execute("""
                    INSERT INTO notifications (recipient_id, actor_id, image_id, action_type)
                    VALUES (%s, %s, %s, 'comment')
                """, (owner_id, current_user.id, image_id))

        # Get current like count for the new comment
        cur.execute("SELECT COUNT(*) FROM comment_likes WHERE comment_id = %s", (comment_id,))
        like_count = cur.fetchone()[0]

        conn.commit()
    finally:
        cur.close()
        conn.close()

    return jsonify({
        'status': 'success',
        'comment': {
            'comment_id': comment_id,
            'name': f'{current_user.first_name} {current_user.last_name}',
            'user_id': current_user.id,
            'text': comment_text,
            'like_count': like_count,
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
        cur.execute("SELECT user_id FROM comments WHERE comment_id = %s", (comment_id,))
        comment = cur.fetchone()

        if not comment:
            return jsonify({'success': False, 'error': 'Comment not found'}), 404

        if comment[0] != current_user.id:
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403

        cur.execute("DELETE FROM comments WHERE comment_id = %s", (comment_id,))
        conn.commit()

        return jsonify({'success': True})

    except Exception as e:
        print("Error deleting comment:", e)
        return jsonify({'success': False, 'error': 'Server error'}), 500

    finally:
        cur.close()
        conn.close()


@app.route('/delete/<int:image_id>', methods=['POST'])
@login_required
def delete_image(image_id):
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    try:
        # Fetch image info, owner, and collaborator
        cur.execute("SELECT id, collaborator_id, image_url FROM images WHERE image_id = %s", (image_id,))
        image = cur.fetchone()

        if not image:
            return jsonify({'success': False, 'error': 'Image not found'}), 404

        owner_id, collaborator_id, image_url = image

        if current_user.id not in (owner_id, collaborator_id):
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403


        # Delete related data if not using ON DELETE CASCADE
        cur.execute("DELETE FROM likes WHERE image_id = %s", (image_id,))
        cur.execute("DELETE FROM comments WHERE image_id = %s", (image_id,))
        cur.execute("DELETE FROM saved_posts WHERE image_id = %s", (image_id,))
        cur.execute("DELETE FROM notifications WHERE image_id = %s", (image_id,))

        # Delete image
        cur.execute("DELETE FROM images WHERE image_id = %s", (image_id,))
        conn.commit()

        # Remove file from server
        if image_url:
            filename = os.path.basename(image_url)
            file_path = os.path.join('/var/data', filename)
            if os.path.exists(file_path):
                os.remove(file_path)

        return jsonify({'success': True})

    except Exception as e:
        print("Error deleting image:", e)
        return jsonify({'success': False, 'error': 'Server error'}), 500

    finally:
        cur.close()
        conn.close()

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
            # Unlike the comment
            cur.execute(
                "DELETE FROM comment_likes WHERE user_id = %s AND comment_id = %s",
                (current_user.id, comment_id)
            )
            status = 'unliked'
        else:
            # Like the comment
            cur.execute(
                "INSERT INTO comment_likes (user_id, comment_id) VALUES (%s, %s)",
                (current_user.id, comment_id)
            )
            status = 'liked'

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
    current_user_id = current_user.id

    try:
        # Optional: Check if comment exists
        cur.execute("SELECT 1 FROM comments WHERE comment_id = %s", (comment_id,))
        if not cur.fetchone():
            return jsonify({'error': 'Comment not found'}), 404

        # Get comment likers
        cur.execute("""
            SELECT u.id, u.first_name || ' ' || u.last_name AS display_name, cl.created_at, u.verified, u.profile_pic
            FROM comment_likes cl
            JOIN users u ON cl.user_id = u.id
            WHERE cl.comment_id = %s
            ORDER BY cl.created_at DESC
        """, (comment_id,))
        likes = cur.fetchall()

        likers = []
        for liker_id, display_name, created_at, verified, profile_pic in likes:
            if liker_id == current_user_id:
                relationship = 'self'
                request_id = None
            else:
                # Check if already friends
                cur.execute("""
                    SELECT 1 FROM friends 
                    WHERE (user1_id = %s AND user2_id = %s)
                       OR (user1_id = %s AND user2_id = %s);
                """, (current_user_id, liker_id, liker_id, current_user_id))
                is_friend = cur.fetchone() is not None

                if is_friend:
                    relationship = 'friends'
                    request_id = None
                else:
                    # Check outgoing friend request
                    cur.execute("""
                        SELECT status FROM friend_requests
                        WHERE sender_id = %s AND receiver_id = %s;
                    """, (current_user_id, liker_id))
                    outgoing = cur.fetchone()

                    if outgoing:
                        status = outgoing[0]
                        if status == 'pending':
                            relationship = 'outgoing_pending'
                        elif status == 'rejected':
                            relationship = 'outgoing_rejected'
                        else:
                            relationship = 'not_friends'
                        request_id = None
                    else:
                        # Check incoming friend request
                        cur.execute("""
                            SELECT request_id FROM friend_requests
                            WHERE sender_id = %s AND receiver_id = %s AND status = 'pending';
                        """, (liker_id, current_user_id))
                        incoming = cur.fetchone()

                        if incoming:
                            relationship = 'incoming_pending'
                            request_id = incoming[0]
                        else:
                            relationship = 'not_friends'
                            request_id = None

            likers.append({
                'id': liker_id,
                'name': display_name,
                'timestamp': created_at.isoformat(),
                'relationship': relationship,
                'request_id': request_id,
                'verified': verified,
                'profile_pic': profile_pic
            })

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

@app.route('/profile/<int:user_id>', methods=['GET', 'POST'])
@login_required
def profile(user_id):
    
    countries = current_app.config['COUNTRIES']
    states = current_app.config['STATES']
    cities = current_app.config['CITIES']
    
    current_user_id = current_user.id

    if request.method == 'POST':
        if current_user.id != user_id:
            flash("You can only update your own cover photo.", "danger")
            return redirect(url_for('profile', user_id=user_id))

        cover_photo = request.files.get('cover_photo')
        if cover_photo and cover_photo.filename != '':
            if allowed_file(cover_photo.filename):
                ext = cover_photo.filename.rsplit('.', 1)[1].lower()
                cover_photo_filename = f"cover_user_{user_id}.{ext}"
                cover_filepath = os.path.join(app.config['COVER_PHOTO_FOLDER'], cover_photo_filename)
                cover_photo.save(cover_filepath)

                conn = psycopg2.connect(
                    host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
                    dbname="ocularis_db",
                    user="ocularis_db_user",
                    password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
                    port=5432
                )
                cur = conn.cursor()
                cur.execute("UPDATE users SET cover_photo = %s WHERE id = %s", (cover_photo_filename, user_id))
                conn.commit()
                cur.close()
                conn.close()

                flash("Cover photo updated!", "success")
                return redirect(url_for('profile', user_id=user_id))
            else:
                flash("Invalid cover photo file type.", "danger")
                return redirect(url_for('profile', user_id=user_id))

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()
    
    cur.execute("""
        SELECT first_name, last_name, role, city, state, country, profile_pic, cover_photo 
        FROM users WHERE id = %s
    """, (user_id,))
    row = cur.fetchone()

    # Convert to a named dict
    profile_user = {
        "first_name": row[0],
        "last_name": row[1],
        "role": row[2],
        "city": row[3],
        "state": row[4],
        "country": row[5],
        "profile_pic": row[6],
        "cover_photo": row[7]
    }

    role = profile_user["role"]
    city = profile_user["city"]
    state = profile_user["state"]
    country = profile_user["country"]
    viewed_user_profile_pic = profile_user["profile_pic"]
    viewed_user_profile_cover = profile_user["cover_photo"]

    # Count number of confirmed friends (mutual connections)
    cur.execute("""
        SELECT COUNT(*) FROM friends 
        WHERE user1_id = %s OR user2_id = %s
    """, (user_id, user_id))
    friend_count = cur.fetchone()[0]
    
    # Fetch friends' full details with friend request relationship logic
    cur.execute("""
        SELECT u.id, u.first_name, u.last_name, u.profile_pic, u.verified
        FROM users u
        JOIN friends f ON (
            (f.user1_id = u.id AND f.user2_id = %s)
            OR (f.user2_id = u.id AND f.user1_id = %s)
        )
        WHERE u.id != %s
    """, (user_id, user_id, user_id))
    friends = cur.fetchall()

    friends_list = []
    for f in friends:
        fid, fname, lname, pfp, verified = f

        # Re-check relationship status (for possible pending/canceled/removed)
        cur.execute("""
            SELECT sender_id, receiver_id, status, request_id
            FROM friend_requests
            WHERE (sender_id = %s AND receiver_id = %s)
            OR (sender_id = %s AND receiver_id = %s)
            LIMIT 1
        """, (user_id, fid, fid, user_id))
        row = cur.fetchone()

        relationship = 'friends'
        request_id = None
        if row:
            sender, receiver, status, req_id = row
            request_id = req_id
            if status == 'pending':
                if receiver == user_id:
                    relationship = 'incoming_pending'
                else:
                    relationship = 'outgoing_pending'
            elif status == 'rejected':
                relationship = 'outgoing_rejected'

        friends_list.append({
            "id": fid,
            "full_name": f"{fname} {lname}",
            "profile_pic": pfp,
            "verified": verified,
            "relationship": relationship,
            "request_id": request_id
        })

    # Fetch images with author and collaborator names for a specific user, with search filtering
    query = request.args.get('query', '').strip()
    like_query = f"%{query}%"

    cur.execute("""
        SELECT 
            images.image_id,                 -- 0
            images.image_url,                -- 1
            images.caption,                  -- 2
            COALESCE(like_count, 0),         -- 3
            images.id,                       -- 4 (author's user ID)
            author.first_name,               -- 5
            author.last_name,                -- 6
            images.created_at,               -- 7
            collaborator.id,                 -- 8
            collaborator.first_name,         -- 9
            collaborator.last_name,          -- 10
            author.profile_pic,              -- 11
            collaborator.profile_pic,        -- 12
            EXISTS (
                SELECT 1 FROM likes 
                WHERE user_id = %s
                AND image_id = images.image_id
            ) AS is_liked
        FROM images
        JOIN users AS author ON images.id = author.id
        LEFT JOIN users AS collaborator ON images.collaborator_id = collaborator.id
        LEFT JOIN (
            SELECT image_id, COUNT(*) AS like_count 
            FROM likes 
            GROUP BY image_id
        ) AS likes ON images.image_id = likes.image_id
        LEFT JOIN image_tags ON images.image_id = image_tags.image_id
        LEFT JOIN hidden_posts hp ON images.image_id = hp.image_id AND hp.user_id = %s
        WHERE hp.user_id IS NULL
        AND (
            images.id = %s OR images.collaborator_id = %s
        )
        AND (
            images.caption ILIKE %s OR
            image_tags.tag ILIKE %s OR
            (author.first_name || ' ' || author.last_name) ILIKE %s OR
            (collaborator.first_name || ' ' || collaborator.last_name) ILIKE %s
        )
        ORDER BY images.created_at DESC;
    """, (
        user_id,      # for EXISTS
        user_id,      # for hidden_posts join
        user_id,      # images.id = user_id
        user_id,      # images.collaborator_id = user_id
        like_query,   # caption
        like_query,   # tag
        like_query,   # author
        like_query    # collaborator
    ))

    images = cur.fetchall()

    # Fetch comments on the user's posts, with like count and like status by the current user
    cur.execute("""
        SELECT 
            comments.comment_id,                                  -- 0
            comments.image_id,                                    -- 1
            users.first_name,                                     -- 2
            comments.comment_text,                                -- 3
            comments.created_at,                                  -- 4
            (SELECT COUNT(*) FROM comment_likes 
            WHERE comment_likes.comment_id = comments.comment_id) AS like_count, -- 5
            comments.user_id,                                     -- 6
            users.profile_pic,                                    -- 7
            EXISTS (                                               -- 8 ✅ is_liked
                SELECT 1 FROM comment_likes 
                WHERE comment_likes.comment_id = comments.comment_id 
                AND comment_likes.user_id = %s
            ) AS is_liked
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.image_id IN (
            SELECT image_id FROM images 
            WHERE id = %s OR collaborator_id = %s
        )
        ORDER BY comments.created_at ASC
    """, (user_id, user_id, user_id))  # user_id repeated because it's used 3 times
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
        SELECT  
            users.first_name || ' ' || users.last_name AS display_name,
            notifications.action_type,
            notifications.image_id,
            notifications.created_at,
            notifications.actor_id,
            users.profile_pic,
            notifications.notification_id
        FROM notifications
        JOIN users ON notifications.actor_id = users.id
        WHERE notifications.recipient_id = %s
        ORDER BY notifications.created_at DESC
    """, (current_user.id,))
    notifications = cur.fetchall()
    
    # Gather unique actor_ids
    actor_ids = list(set([n[4] for n in notifications]))

            # Prepare dictionary to hold actor_id → user profile details
    actor_details = {}

            # Fetch full details for each actor_id
    for actor_id in actor_ids:
        cur.execute("""
            SELECT first_name, last_name, role, city, state, country, 
                profile_pic, cover_photo, skills, preferences, experience_level,
                facebook, instagram, x, linkedin, telegram, email
            FROM users WHERE id = %s
        """, (actor_id,))
        actor_row = cur.fetchone()

        if actor_row:
            countries = current_app.config['COUNTRIES']
            states = current_app.config['STATES']

            # Get raw codes
            actor_city = actor_row[3]
            actor_state_code = actor_row[4]
            actor_country_code = actor_row[5]

            # Map ISO2 to country name
            iso_to_country = {c["iso2"]: c["name"] for c in countries}
            readable_country = iso_to_country.get(actor_country_code, actor_country_code)

            # Filter states only for this country
            filtered_states = [s for s in states if s["country_code"] == actor_country_code]
            state_code_to_name = {s["state_code"]: s["name"] for s in filtered_states}
            readable_state = state_code_to_name.get(actor_state_code, actor_state_code)

            # Match city correctly
            matched_city = next(
                (c for c in cities if c["name"] == actor_city and c["state_code"] == actor_state_code and c["country_code"] == actor_country_code),
                None
            )
            readable_city = matched_city["name"] if matched_city else actor_city

            location_display = ", ".join(filter(None, [readable_city, readable_state, readable_country]))

            actor_details[actor_id] = {
                "user_id": actor_id,
                "full_name": f"{actor_row[0]} {actor_row[1]}",
                "role": actor_row[2],
                "city": city,
                "state": actor_state_code,
                "country": actor_country_code,
                "location_display": location_display,  # ✅ new key
                "profile_pic": actor_row[6],
                "cover_photo": actor_row[7],
                "skills": actor_row[8],
                "preferences": actor_row[9],
                "experience_level": actor_row[10],
                "facebook": actor_row[11],
                "instagram": actor_row[12],
                "x": actor_row[13],
                "linkedin": actor_row[14],
                "telegram": actor_row[15],
                "email": actor_row[16]
            }

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

    # New query to get current user's profile_pic
    cur.execute("SELECT profile_pic FROM users WHERE id = %s", (current_user.id,))
    result = cur.fetchone()

    if result and result[0] and result[0] != 'pfp.jpg':
        profile_pic_url = url_for('profile_pics', filename=result[0])
    else:
        profile_pic_url = url_for('static', filename='pfp.jpg')
    
    cur.close()
    conn.close()

    # Determine whether to disable "Add Friend" button
    disable_add_friend = (
        is_friend or
        current_user_id == user_id or
        incoming_request is not None or # you cannot add if they already sent you a request
        outgoing_request is not None
    )

    # Map ISO2 to country name
    iso_to_country = {c["iso2"]: c["name"] for c in countries}
    readable_country = iso_to_country.get(country, country)

    # Filter states only for this country
    filtered_states = [s for s in states if s["country_code"] == country]
    state_code_to_name = {s["state_code"]: s["name"] for s in filtered_states}
    readable_state = state_code_to_name.get(state, state)

    # ✅ Safely match city with full triplet
    matched_city = next(
        (c for c in cities if c["name"] == city and c["state_code"] == state and c["country_code"] == country),
        None
    )
    readable_city = matched_city["name"] if matched_city else city

    location = ", ".join(filter(None, [readable_city, readable_state, readable_country]))

    return render_template(
        "profile.html",
        current_page='profile',
        user=profile_user,
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
        saved_image_ids=saved_image_ids,
        profile_pic_url=profile_pic_url,
        viewed_user_profile_pic=viewed_user_profile_pic,
        viewed_user_profile_cover=viewed_user_profile_cover,
        actor_details=actor_details,
        friends_list=friends_list
    )

@app.route('/send_request/<int:receiver_id>', methods=['POST'])
@login_required
def send_request(receiver_id):
    sender_id = current_user.id

    # ❌ Block if not verified
    if not current_user.verified:
        message = "You must verify your account before sending friend requests."
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(success=False, message=message), 403
        flash(message)
        return redirect(request.referrer or url_for('feed'))

    if sender_id == receiver_id:
        message = "You cannot send a friend request to yourself."
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(success=False, message=message), 400
        flash(message)
        return redirect(request.referrer or url_for('feed'))

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()

    try:
        user1_id, user2_id = sorted((sender_id, receiver_id))

        # ✅ Prevent if already friends
        cur.execute("""
            SELECT 1 FROM friends
            WHERE user1_id = %s AND user2_id = %s;
        """, (user1_id, user2_id))
        if cur.fetchone():
            message = "You are already friends with this user."
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(success=False, message=message), 409
            flash(message)
            return redirect(request.referrer or url_for('feed'))

        # ✅ Check for mutual request: if receiver already sent you a request
        cur.execute("""
            SELECT request_id FROM friend_requests
            WHERE sender_id = %s AND receiver_id = %s AND status = 'pending';
        """, (receiver_id, sender_id))
        mutual_request = cur.fetchone()

        if mutual_request:
            # If mutual request exists, don't insert another
            request_id = mutual_request[0]
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(success=True, status="incoming_pending", request_id=request_id)
            flash("This user already sent you a request.")
            return redirect(request.referrer or url_for('feed'))

        # ✅ Check if request already exists
        cur.execute("""
            SELECT 1 FROM friend_requests
            WHERE sender_id = %s AND receiver_id = %s AND status = 'pending';
        """, (sender_id, receiver_id))
        if cur.fetchone():
            message = "Friend request already sent."
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(success=False, message=message), 409
            flash(message)
            return redirect(request.referrer or url_for('feed'))

        # ✅ Allow resend after rejection
        cur.execute("""
            DELETE FROM friend_requests
            WHERE sender_id = %s AND receiver_id = %s AND status = 'rejected';
        """, (sender_id, receiver_id))
        conn.commit()

        # ✅ Insert new request and return its ID
        cur.execute("""
            INSERT INTO friend_requests (sender_id, receiver_id, status, created_at)
            VALUES (%s, %s, 'pending', NOW())
            RETURNING request_id;
        """, (sender_id, receiver_id))
        request_id = cur.fetchone()[0]
        conn.commit()

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(success=True, message="Friend request sent.", request_id=request_id)

        flash("Friend request sent.")

    except Exception as e:
        conn.rollback()
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(success=False, message=str(e)), 500
        flash(f"An error occurred: {e}")
    finally:
        cur.close()
        conn.close()

    return redirect(request.referrer or url_for('feed'))


@app.route('/unfriend/<int:other_user_id>', methods=['POST'])
@login_required
def unfriend(other_user_id):
    user_id = current_user.id

    if user_id == other_user_id:
        message = "You cannot unfriend yourself."
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(success=False, message=message), 400
        flash(message)
        return redirect(request.referrer or url_for('profile', user_id=other_user_id))

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()

    try:
        user1_id, user2_id = sorted((user_id, other_user_id))
        cur.execute("""
            DELETE FROM friends
            WHERE user1_id = %s AND user2_id = %s;
        """, (user1_id, user2_id))

        cur.execute("""
            DELETE FROM friend_requests
            WHERE (sender_id = %s AND receiver_id = %s)
               OR (sender_id = %s AND receiver_id = %s);
        """, (user_id, other_user_id, other_user_id, user_id))

        conn.commit()

        message = "You have unfriended this user and cleared any past friend requests."
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(success=True, message=message)

        flash(message)
    except Exception as e:
        conn.rollback()
        error_msg = f"Error while unfriending: {e}"
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(success=False, message=error_msg), 500
        flash(error_msg)
    finally:
        cur.close()
        conn.close()

    return redirect(request.referrer or url_for('profile', user_id=other_user_id))




@app.route('/cancel_request/<int:user_id>', methods=['POST'])
@login_required
def cancel_request(user_id):
    sender_id = current_user.id

    if sender_id == user_id:
        message = "You cannot cancel a request to yourself."
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(success=False, message=message), 400
        flash(message)
        return redirect(request.referrer or url_for('profile', user_id=user_id))


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
            DELETE FROM friend_requests
            WHERE sender_id = %s AND receiver_id = %s AND status = 'pending';
        """, (sender_id, user_id))
        conn.commit()

        message = "Friend request cancelled."
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(success=True, message=message)

        flash(message)
    except Exception as e:
        conn.rollback()
        error_msg = f"Error cancelling request: {e}"
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify(success=False, message=error_msg), 500
        flash(error_msg)
    finally:
        cur.close()
        conn.close()

    return redirect(request.referrer or url_for('profile', user_id=user_id))

@app.route('/accept_request/<int:request_id>', methods=['POST'])
@login_required
def accept_request(request_id):
    if not current_user.verified:
        message = "Verify your account before accepting requests."
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({'success': False, 'message': message}), 403
        flash(message)
        return redirect(request.referrer or url_for('feed'))

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
        cur.execute("""
            SELECT sender_id FROM friend_requests 
            WHERE request_id = %s AND receiver_id = %s AND status = 'pending';
        """, (request_id, receiver_id))
        row = cur.fetchone()

        if not row:
            message = "Request not found or already handled."
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({'success': False, 'message': message}), 404
            flash(message)
            return redirect(request.referrer or url_for('feed'))

        sender_id = row[0]
        user1_id, user2_id = sorted((sender_id, receiver_id))

        cur.execute("SELECT 1 FROM friends WHERE user1_id = %s AND user2_id = %s;", (user1_id, user2_id))
        if cur.fetchone():
            message = "Already friends."
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({'success': False, 'message': message}), 400
            flash(message)
            return redirect(request.referrer or url_for('feed'))

        cur.execute("UPDATE friend_requests SET status = 'accepted' WHERE request_id = %s;", (request_id,))
        cur.execute("INSERT INTO friends (user1_id, user2_id) VALUES (%s, %s);", (user1_id, user2_id))
        conn.commit()

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({'success': True, 'message': "Friend request accepted."})


        flash("Friend request accepted.")
    except Exception as e:
        conn.rollback()
        error_msg = f"Error: {e}"
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({'success': False, 'message': error_msg}), 500
        flash(error_msg)
    finally:
        cur.close()
        conn.close()

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({'success': True, 'message': "Friend request accepted."})
    return redirect(request.referrer or url_for('feed'))


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
        cur.execute("DELETE FROM friend_requests WHERE request_id = %s;", (request_id,))
        conn.commit()

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({'success': True, 'message': "Friend request accepted."})


        flash("Friend request rejected.")
    except Exception as e:
        conn.rollback()
        error_msg = f"Error: {e}"
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({'success': False, 'message': error_msg}), 500
        flash(error_msg)
    finally:
        cur.close()
        conn.close()

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({'success': True, 'message': "Friend request rejected."})
    return redirect(request.referrer or url_for('feed'))


@app.route('/pairup')
@login_required
def pairup():
    user_id = current_user.id
    now_utc = datetime.now(timezone.utc)

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    # 🔒 Check for match lock (based on collab_actions)
    cur.execute("""
        SELECT action_time FROM collab_actions
        WHERE user_id = %s
        ORDER BY action_time DESC
        LIMIT 1
    """, (user_id,))
    result = cur.fetchone()

    match_locked = False
    browse_locked = False
    time_remaining = None

    if result:
        last_action_time = result[0]

        if last_action_time.tzinfo is None:
            manila = pytz.timezone('Asia/Manila')
            last_action_time = manila.localize(last_action_time).astimezone(timezone.utc)

        time_diff = now_utc - last_action_time

        if time_diff < timedelta(minutes=3):
            match_locked = True
            browse_locked = True
            time_remaining = str(timedelta(minutes=3) - time_diff).split('.')[0]  # hh:mm:ss

    # Fetch notifications
    cur.execute("""
        SELECT 
            users.first_name || ' ' || users.last_name AS display_name,
            notifications.action_type,
            notifications.image_id,
            notifications.created_at,
            notifications.actor_id,
            users.profile_pic,
            notifications.notification_id
        FROM notifications
        JOIN users ON notifications.actor_id = users.id
        WHERE notifications.recipient_id = %s
        ORDER BY notifications.created_at DESC
    """, (current_user.id,))
    notifications = cur.fetchall()
    
            # Gather unique actor_ids
    actor_ids = list(set([n[4] for n in notifications]))

            # Prepare dictionary to hold actor_id → user profile details
    actor_details = {}

            # Fetch full details for each actor_id
    for actor_id in actor_ids:
        cur.execute("""
            SELECT first_name, last_name, role, city, state, country, 
                profile_pic, cover_photo, skills, preferences, experience_level,
                facebook, instagram, x, linkedin, telegram, email
            FROM users WHERE id = %s
        """, (actor_id,))
        user = cur.fetchone()

        if user:
                countries = current_app.config['COUNTRIES']
                states = current_app.config['STATES']

                # Get raw codes
                city = user[3]
                state_code = user[4]
                country_code = user[5]

                # Look up readable names
                iso_to_country = {c["iso2"]: c["name"] for c in countries}
                readable_country = iso_to_country.get(country_code, country_code)

                # Filter states by selected country
                filtered_states = [s for s in states if s["country_code"] == country_code]
                state_code_to_name = {s["state_code"]: s["name"] for s in filtered_states}
                readable_state = state_code_to_name.get(state_code, state_code)

                # Display-friendly location string
                location_display = ", ".join(filter(None, [city, readable_state, readable_country]))

                actor_details[actor_id] = {
                    "user_id": actor_id,
                    "full_name": f"{user[0]} {user[1]}",
                    "role": user[2],
                    "city": city,
                    "state": state_code,
                    "country": country_code,
                    "location_display": location_display,  # ✅ new key
                    "profile_pic": user[6],
                    "cover_photo": user[7],
                    "skills": user[8],
                    "preferences": user[9],
                    "experience_level": user[10],
                    "facebook": user[11],
                    "instagram": user[12],
                    "x": user[13],
                    "linkedin": user[14],
                    "telegram": user[15],
                    "email": user[16]
                }

    # Fetch friend requests
    cur.execute("""
        SELECT fr.request_id, fr.sender_id, u.first_name, u.last_name, fr.created_at
        FROM friend_requests fr
        JOIN users u ON fr.sender_id = u.id
        WHERE fr.receiver_id = %s AND fr.status = 'pending'
        ORDER BY fr.created_at DESC
    """, (current_user.id,))
    requests = cur.fetchall()

    # Fetch recent matches with viewed user's profile_pic added at the end
    cur.execute("""
        SELECT 
            u.id,                 -- match[0]
            u.first_name,         -- match[1]
            u.last_name,          -- match[2]
            rm.matched_at,        -- match[3]
            u.profile_pic         -- match[4] ✅ viewed user's profile_pic
        FROM recent_matches rm
        JOIN users u ON rm.matched_user_id = u.id
        WHERE rm.user_id = %s
        ORDER BY rm.matched_at DESC
    """, (current_user.id,))
    recent_matches = cur.fetchall()

    # New query to get current user's profile_pic
    cur.execute("SELECT profile_pic FROM users WHERE id = %s", (current_user.id,))
    result = cur.fetchone()

    if result and result[0] and result[0] != 'pfp.jpg':
        profile_pic_url = url_for('profile_pics', filename=result[0])
    else:
        profile_pic_url = url_for('static', filename='pfp.jpg')

    cur.close()
    conn.close()

    return render_template(
        "pairup.html",
        user=current_user,
        notifications=notifications,
        requests=requests,
        recent_matches=recent_matches,
        verified=current_user.verified,
        profile_pic_url=profile_pic_url,
        match_locked=match_locked,
        browse_locked=browse_locked,
        time_remaining=time_remaining,
        actor_details=actor_details
    )

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
            notifications.actor_id,
            users.profile_pic,
            notifications.notification_id
        FROM notifications
        JOIN users ON notifications.actor_id = users.id
        WHERE notifications.recipient_id = %s
        ORDER BY notifications.created_at DESC
    """, (user_id,))
    notifications = cur.fetchall()
    
            # Gather unique actor_ids
    actor_ids = list(set([n[4] for n in notifications]))

            # Prepare dictionary to hold actor_id → user profile details
    actor_details = {}

            # Fetch full details for each actor_id
    for actor_id in actor_ids:
        cur.execute("""
            SELECT first_name, last_name, role, city, state, country, 
                profile_pic, cover_photo, skills, preferences, experience_level,
                facebook, instagram, x, linkedin, telegram, email
            FROM users WHERE id = %s
        """, (actor_id,))
        user = cur.fetchone()

        if user:
                countries = current_app.config['COUNTRIES']
                states = current_app.config['STATES']

                # Get raw codes
                city = user[3]
                state_code = user[4]
                country_code = user[5]

                # Look up readable names
                iso_to_country = {c["iso2"]: c["name"] for c in countries}
                readable_country = iso_to_country.get(country_code, country_code)

                # Filter states by selected country
                filtered_states = [s for s in states if s["country_code"] == country_code]
                state_code_to_name = {s["state_code"]: s["name"] for s in filtered_states}
                readable_state = state_code_to_name.get(state_code, state_code)

                # Display-friendly location string
                location_display = ", ".join(filter(None, [city, readable_state, readable_country]))

                actor_details[actor_id] = {
                    "user_id": actor_id,
                    "full_name": f"{user[0]} {user[1]}",
                    "role": user[2],
                    "city": city,
                    "state": state_code,
                    "country": country_code,
                    "location_display": location_display,  # ✅ new key
                    "profile_pic": user[6],
                    "cover_photo": user[7],
                    "skills": user[8],
                    "preferences": user[9],
                    "experience_level": user[10],
                    "facebook": user[11],
                    "instagram": user[12],
                    "x": user[13],
                    "linkedin": user[14],
                    "telegram": user[15],
                    "email": user[16]
                }

    # Fetch friend requests
    cur.execute("""
        SELECT fr.request_id, fr.sender_id, u.first_name, u.last_name, fr.created_at
        FROM friend_requests fr
        JOIN users u ON fr.sender_id = u.id
        WHERE fr.receiver_id = %s AND fr.status = 'pending'
        ORDER BY fr.created_at DESC
    """, (user_id,))
    requests = cur.fetchall()

    # New query to get current user's profile_pic
    cur.execute("SELECT profile_pic FROM users WHERE id = %s", (current_user.id,))
    result = cur.fetchone()

    if result and result[0] and result[0] != 'pfp.jpg':
        profile_pic_url = url_for('profile_pics', filename=result[0])
    else:
        profile_pic_url = url_for('static', filename='pfp.jpg')


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
    cur.execute("SELECT id, first_name, last_name, role, profile_pic, facebook, email FROM users WHERE id = ANY(%s)", (user_ids,))
    name_rows = cur.fetchall()

    name_map = {
        row[0]: {
            "id": row[0],
            "first_name": row[1],
            "last_name": row[2],
            "role": row[3],
            "profile_pic": row[4],
            "facebook": row[5],
            "email": row[6]
        }
        for row in name_rows
    }

    users_list = []
    for user in similar_users_df.to_dict(orient='records'):
        details = name_map.get(user["user"], {})
        user["id"] = details.get("id", user["user"])
        user["first_name"] = details.get("first_name", "Unknown")
        user["last_name"] = details.get("last_name", "")
        user["role"] = details.get("role", "")
        user["facebook"] = details.get("facebook", "")
        user["email"] = details.get("email", "")


        # ✅ Add profile_pic_url
        profile_pic = details.get("profile_pic")
        user["profile_pic_url"] = (
            url_for("profile_pics", filename=profile_pic)
            if profile_pic and profile_pic != "pfp.jpg"
            else url_for("static", filename="pfp.jpg")
        )

        # 🔽 Fetch skills, preferences, experience_level for this user
        cur = conn.cursor()
        cur.execute("""
            SELECT skills, preferences, experience_level
            FROM users
            WHERE id = %s
        """, (user["id"],))
        extra = cur.fetchone()
        cur.close()

        if extra:
            user["skills"] = extra[0] or []
            user["preferences"] = extra[1] or []
            user["experience_level"] = extra[2] or 0
        else:
            user["skills"] = []
            user["preferences"] = []
            user["experience_level"] = 0

        users_list.append(user)
        
    cur.close()
    conn.close()    

    return render_template("match.html", user=current_user, current_page='match', users=users_list[:3], notifications=notifications, requests=requests, verified=current_user.verified, profile_pic_url=profile_pic_url, actor_details=actor_details)

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

    return jsonify({
        'message': 'Notification sent to collaborator',
        'redirect_url': url_for('pairup')
    }), 201

@app.route('/decline_match', methods=['POST'])
@login_required
def decline_match():
    data = request.get_json()
    try:
        other_user_id = int(data.get('other_user_id'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid user ID'}), 400

    user_id = current_user.id
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
                # Delete the mutual match
                cur.execute("""
                    DELETE FROM recent_matches
                    WHERE (user_id = %s AND matched_user_id = %s)
                       OR (user_id = %s AND matched_user_id = %s)
                """, (user_id, other_user_id, other_user_id, user_id))

                # Delete the notification
                cur.execute("""
                    DELETE FROM notifications
                    WHERE ((recipient_id = %s AND actor_id = %s) OR (recipient_id = %s AND actor_id = %s))
                        AND action_type = 'collab_check'
                """, (user_id, other_user_id, other_user_id, user_id))

        return jsonify({'message': 'Match and notification removed'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

def get_random_users(current_user_id):
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    # Exclude current user and accepted friends
    cur.execute("""
        SELECT id, first_name, last_name, profile_pic, verified
        FROM users
        WHERE id != %s
          AND id NOT IN (
              SELECT CASE 
                         WHEN sender_id = %s THEN receiver_id
                         ELSE sender_id
                     END
              FROM friend_requests
              WHERE (sender_id = %s OR receiver_id = %s)
                AND status = 'accepted'
          )
        ORDER BY RANDOM()
        LIMIT 12
    """, (current_user_id, current_user_id, current_user_id, current_user_id))
    user_rows = cur.fetchall()

    users = []
    for uid, fname, lname, pfp, verified in user_rows:
        # Get relationship status
        cur.execute("""
            SELECT sender_id, receiver_id, status, request_id
            FROM friend_requests
            WHERE (sender_id = %s AND receiver_id = %s)
               OR (sender_id = %s AND receiver_id = %s)
            LIMIT 1
        """, (current_user_id, uid, uid, current_user_id))
        row = cur.fetchone()

        relationship = 'not_friends'
        request_id = None
        if row:
            sender, receiver, status, req_id = row
            request_id = req_id
            if status == 'pending':
                if receiver == current_user_id:
                    relationship = 'incoming_pending'
                else:
                    relationship = 'outgoing_pending'
            elif status == 'rejected':
                relationship = 'outgoing_rejected'

        users.append({
            'id': uid,
            'first_name': fname,
            'last_name': lname,
            'profile_pic': pfp,
            'verified': verified,
            'relationship': relationship,
            'request_id': request_id
        })

    cur.close()
    conn.close()
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

    # --- Fetch notifications ---
    cur.execute("""
        SELECT 
            users.first_name || ' ' || users.last_name AS display_name,
            notifications.action_type,
            notifications.image_id,
            notifications.created_at,
            notifications.actor_id,
            users.profile_pic,
            notifications.notification_id
        FROM notifications
        JOIN users ON notifications.actor_id = users.id
        WHERE notifications.recipient_id = %s
        ORDER BY notifications.created_at DESC
    """, (user_id,))
    notifications = cur.fetchall()

    # --- Get actor details ---
    actor_ids = list(set([n[4] for n in notifications]))
    actor_details = {}
    for actor_id in actor_ids:
        cur.execute("""
            SELECT first_name, last_name, role, city, state, country, 
                profile_pic, cover_photo, skills, preferences, experience_level,
                facebook, instagram, x, linkedin, telegram, email
            FROM users WHERE id = %s
        """, (actor_id,))
        user = cur.fetchone()
        if user:
            countries = current_app.config['COUNTRIES']
            states = current_app.config['STATES']

            city, state_code, country_code = user[3], user[4], user[5]
            iso_to_country = {c["iso2"]: c["name"] for c in countries}
            readable_country = iso_to_country.get(country_code, country_code)
            filtered_states = [s for s in states if s["country_code"] == country_code]
            state_code_to_name = {s["state_code"]: s["name"] for s in filtered_states}
            readable_state = state_code_to_name.get(state_code, state_code)
            location_display = ", ".join(filter(None, [city, readable_state, readable_country]))

            actor_details[actor_id] = {
                "user_id": actor_id,
                "full_name": f"{user[0]} {user[1]}",
                "role": user[2],
                "city": city,
                "state": state_code,
                "country": country_code,
                "location_display": location_display,
                "profile_pic": user[6],
                "cover_photo": user[7],
                "skills": user[8],
                "preferences": user[9],
                "experience_level": user[10],
                "facebook": user[11],
                "instagram": user[12],
                "x": user[13],
                "linkedin": user[14],
                "telegram": user[15],
                "email": user[16]
            }

    # --- Friend requests ---
    cur.execute("""
        SELECT fr.request_id, fr.sender_id, u.first_name, u.last_name, fr.created_at
        FROM friend_requests fr
        JOIN users u ON fr.sender_id = u.id
        WHERE fr.receiver_id = %s AND fr.status = 'pending'
        ORDER BY fr.created_at DESC
    """, (user_id,))
    requests = cur.fetchall()

    # --- Current user profile pic ---
    cur.execute("SELECT profile_pic FROM users WHERE id = %s", (user_id,))
    result = cur.fetchone()
    profile_pic_url = url_for('profile_pics', filename=result[0]) if result and result[0] and result[0] != 'pfp.jpg' else url_for('static', filename='pfp.jpg')

    # --- Get filtered random users ---
    users = get_random_users(user_id)

    return render_template(
        'browse.html',
        user=current_user,
        users=users,
        notifications=notifications,
        requests=requests,
        verified=current_user.verified,
        profile_pic_url=profile_pic_url,
        actor_details=actor_details
    )
        
UPLOAD_FOLDER = '/var/data'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['COVER_PHOTO_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/profile_pics/<filename>')
def profile_pics(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/cover_photos/<filename>')
def cover_photos(filename):
    return send_from_directory(app.config['COVER_PHOTO_FOLDER'], filename)


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

    # Fetch profile and cover photos
    cur.execute("SELECT profile_pic, cover_photo FROM users WHERE id = %s", (user_id,))
    result = cur.fetchone()
    profile_pic_url = url_for('profile_pics', filename=result[0]) if result and result[0] and result[0] != 'pfp.jpg' else url_for('static', filename='pfp.jpg')
    cover_photo_url = url_for('cover_photos', filename=result[1]) if result and result[1] and result[1] != 'default_cover.png' else url_for('static', filename='default_cover.png')

    if request.method == 'POST':
        # Form values
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        role = request.form.get('role')
        country = request.form.get('country')
        state = request.form.get('state')
        city = request.form.get('city')
        experience_level = request.form.get('experience_level')
        skills_list = request.form.getlist('skills[]')
        preferences_list = request.form.getlist('preferences[]')
        facebook = request.form.get('facebook')
        instagram = request.form.get('instagram')
        x = request.form.get('x')
        linkedin = request.form.get('linkedin')
        telegram = request.form.get('telegram')

        # Handle uploads
        profile_pic = request.files.get('profile_pic')
        if profile_pic and profile_pic.filename != '':
            if allowed_file(profile_pic.filename):
                ext = profile_pic.filename.rsplit('.', 1)[1].lower()
                filename = f"pfp_user_{user_id}.{ext}"
                profile_pic.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                cur.execute("UPDATE users SET profile_pic = %s WHERE id = %s", (filename, user_id))
            else:
                flash("Invalid profile picture file type.", "danger")
                cur.close()
                conn.close()
                return redirect(url_for('settings'))

        cover_photo = request.files.get('cover_photo')
        if cover_photo and cover_photo.filename != '':
            if allowed_file(cover_photo.filename):
                ext = cover_photo.filename.rsplit('.', 1)[1].lower()
                filename = f"cover_user_{user_id}.{ext}"
                cover_photo.save(os.path.join(app.config['COVER_PHOTO_FOLDER'], filename))
                cur.execute("UPDATE users SET cover_photo = %s WHERE id = %s", (filename, user_id))
            else:
                flash("Invalid cover photo file type.", "danger")
                cur.close()
                conn.close()
                return redirect(url_for('settings'))

        # Update user info
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
            first_name, last_name, role, country, state, city,
            skills_list, preferences_list, experience_level,
            facebook, instagram, x, linkedin, telegram,
            user_id
        ))

        conn.commit()
        cur.close()
        conn.close()

        flash("Settings updated successfully.", "success")
        return redirect(url_for('settings'))

    # GET: fetch user data
    cur.execute("""
        SELECT first_name, last_name, role, country, state, city, skills, preferences,
               experience_level, facebook, instagram, x, linkedin, telegram
        FROM users WHERE id = %s
    """, (user_id,))
    user_row = cur.fetchone()

    # Notifications
    cur.execute("""
        SELECT users.first_name || ' ' || users.last_name AS display_name,
               notifications.action_type, notifications.image_id, notifications.created_at, 
               notifications.actor_id, users.profile_pic, notifications.notification_id
        FROM notifications
        JOIN users ON notifications.actor_id = users.id
        WHERE notifications.recipient_id = %s
        ORDER BY notifications.created_at DESC
    """, (user_id,))
    notifications = cur.fetchall()

    actor_ids = list(set([n[4] for n in notifications]))
    actor_details = {}

    for actor_id in actor_ids:
        cur.execute("""
            SELECT first_name, last_name, role, city, state, country, 
                   profile_pic, cover_photo, skills, preferences, experience_level,
                   facebook, instagram, x, linkedin, telegram, email
            FROM users WHERE id = %s
        """, (actor_id,))
        actor_row = cur.fetchone()
        
        if actor_row:
            countries = current_app.config['COUNTRIES']
            states = current_app.config['STATES']

            # Get raw codes
            city = actor_row[3]
            state_code = actor_row[4]
            country_code = actor_row[5]

            # Look up readable names
            iso_to_country = {c["iso2"]: c["name"] for c in countries}
            readable_country = iso_to_country.get(country_code, country_code)

            # Filter states by selected country
            filtered_states = [s for s in states if s["country_code"] == country_code]
            state_code_to_name = {s["state_code"]: s["name"] for s in filtered_states}
            readable_state = state_code_to_name.get(state_code, state_code)

            # Display-friendly location string
            location_display = ", ".join(filter(None, [city, readable_state, readable_country]))

            actor_details[actor_id] = {
                "user_id": actor_id,
                "full_name": f"{actor_row[0]} {actor_row[1]}",
                "role": actor_row[2],
                "city": city,
                "state": state_code,
                "country": country_code,
                "location_display": location_display,  # ✅ new key
                "profile_pic": actor_row[6],
                "cover_photo": actor_row[7],
                "skills": actor_row[8],
                "preferences": actor_row[9],
                "experience_level": actor_row[10],
                "facebook": actor_row[11],
                "instagram": actor_row[12],
                "x": actor_row[13],
                "linkedin": actor_row[14],
                "telegram": actor_row[15],
                "email": actor_row[16]
            }

    # Friend Requests
    cur.execute("""
        SELECT fr.request_id, fr.sender_id, u.first_name, u.last_name, fr.created_at
        FROM friend_requests fr
        JOIN users u ON fr.sender_id = u.id
        WHERE fr.receiver_id = %s AND fr.status = 'pending'
        ORDER BY fr.created_at DESC
    """, (user_id,))
    requests = cur.fetchall()
    
    cur.execute("""
        SELECT notify_likes, notify_comments, notify_requests
        FROM users
        WHERE id = %s
    """, (current_user.id,))
    prefs = cur.fetchone()

    cur.close()
    conn.close()

    if user_row:
        user_dict = {
            'first_name': user_row[0],
            'last_name': user_row[1],
            'role': user_row[2],
            'country': user_row[3],
            'state': user_row[4],
            'city': user_row[5],
            'skills': ', '.join(user_row[6]) if user_row[6] else '',
            'preferences': ', '.join(user_row[7]) if user_row[7] else '',
            'experience_level': user_row[8],
            'facebook': user_row[9],
            'instagram': user_row[10],
            'x': user_row[11],
            'linkedin': user_row[12],
            'telegram': user_row[13]
        }

        return render_template(
            'settings.html',
            user=user_dict,  # form fields use this
            current_user=current_user,  # base.html and global nav uses this
            countries=app.config['COUNTRIES'],
            categories=[
                "Typography", "Branding", "Advertising", "Graphic Design", "Illustration",
                "3D Design", "Animation", "Packaging", "Infographics", "UI/UX Design"
            ],
            experience_levels=[
                (1, "Beginner"),
                (2, "Intermediate"),
                (3, "Advanced"),
                (4, "Expert")
            ],
            verified=current_user.verified,
            profile_pic_url=profile_pic_url,
            cover_photo_url=cover_photo_url,
            notifications=notifications,
            requests=requests,
            actor_details=actor_details,
            notify_likes=prefs[0],
            notify_comments=prefs[1],
            notify_requests=prefs[2]
        )
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
    query = request.args.get('query', '').strip()
    like_query = f"%{query}%"
    user_id = current_user.id

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    try:
        # 1. Fetch saved posts with search filter
        cur.execute("""
            SELECT 
                images.image_id,
                images.image_url,
                images.caption,
                COALESCE(like_counts.count, 0),
                author.id AS author_id,
                author.first_name,
                author.last_name,
                images.created_at,
                collaborator.id AS collaborator_id,
                collaborator.first_name,
                collaborator.last_name,
                author.profile_pic,
                collaborator.profile_pic,
                EXISTS (
                    SELECT 1 FROM likes 
                    WHERE user_id = %s AND image_id = images.image_id
                ) AS is_liked
            FROM saved_posts
            JOIN images ON saved_posts.image_id = images.image_id
            JOIN users AS author ON images.id = author.id
            LEFT JOIN users AS collaborator ON images.collaborator_id = collaborator.id
            LEFT JOIN (
                SELECT image_id, COUNT(*) AS count
                FROM likes
                GROUP BY image_id
            ) AS like_counts ON images.image_id = like_counts.image_id
            LEFT JOIN image_tags ON images.image_id = image_tags.image_id
            LEFT JOIN hidden_posts hp ON images.image_id = hp.image_id AND hp.user_id = %s
            WHERE saved_posts.user_id = %s
              AND hp.user_id IS NULL
              AND (
                    images.caption ILIKE %s OR
                    image_tags.tag ILIKE %s OR
                    (author.first_name || ' ' || author.last_name) ILIKE %s OR
                    (collaborator.first_name || ' ' || collaborator.last_name) ILIKE %s
                )
            GROUP BY 
                images.image_id, images.image_url, images.caption, images.created_at,
                author.id, author.first_name, author.last_name, author.profile_pic,
                collaborator.id, collaborator.first_name, collaborator.last_name, collaborator.profile_pic,
                like_counts.count, saved_posts.saved_at
            ORDER BY saved_posts.saved_at DESC;
        """, (user_id, user_id, user_id, like_query, like_query, like_query, like_query))

        saved_posts = cur.fetchall()

        # 2. Comments, Likes, Comment Likes
        all_comments = {}
        likes_data = {}
        comment_likes_data = {}

        for post in saved_posts:
            image_id = post[0]

            # Comments with like status
            cur.execute("""
                SELECT 
                    comments.comment_id,                                  -- 0
                    comments.image_id,                                    -- 1
                    users.first_name || ' ' || users.last_name AS display_name,  -- 2
                    comments.comment_text,                                -- 3
                    comments.created_at,                                  -- 4
                    COALESCE(like_count, 0),                              -- 5
                    comments.user_id,                                     -- 6
                    users.profile_pic,                                    -- 7
                    EXISTS (                                              -- 8 ✅ is_liked by current user
                        SELECT 1 FROM comment_likes 
                        WHERE comment_likes.comment_id = comments.comment_id 
                        AND comment_likes.user_id = %s
                    ) AS is_liked
                FROM comments
                JOIN users ON comments.user_id = users.id
                LEFT JOIN (
                    SELECT comment_id, COUNT(*) AS like_count
                    FROM comment_likes
                    GROUP BY comment_id
                ) AS cl ON comments.comment_id = cl.comment_id
                WHERE comments.image_id = %s
                ORDER BY comments.created_at ASC
            """, (user_id, image_id))

            comments = cur.fetchall()
            all_comments[image_id] = comments

            # Likes per image
            cur.execute("""
                SELECT u.first_name || ' ' || u.last_name AS display_name, l.created_at
                FROM likes l
                JOIN users u ON l.user_id = u.id
                WHERE l.image_id = %s
                ORDER BY l.created_at DESC
            """, (image_id,))
            likes_data[image_id] = cur.fetchall()

            # Comment likes
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

        # 3. Notifications
        cur.execute("""
            SELECT users.first_name || ' ' || users.last_name AS display_name,
                   notifications.action_type, notifications.image_id, notifications.created_at,
                   notifications.actor_id, users.profile_pic, notifications.notification_id
            FROM notifications
            JOIN users ON notifications.actor_id = users.id
            WHERE notifications.recipient_id = %s
            ORDER BY notifications.created_at DESC
        """, (user_id,))
        notifications = cur.fetchall()

        # 4. Actor Details
        actor_ids = list(set([n[4] for n in notifications]))
        actor_details = {}

        countries = current_app.config['COUNTRIES']
        states = current_app.config['STATES']
        iso_to_country = {c["iso2"]: c["name"] for c in countries}

        for actor_id in actor_ids:
            cur.execute("""
                SELECT first_name, last_name, role, city, state, country, 
                    profile_pic, cover_photo, skills, preferences, experience_level,
                    facebook, instagram, x, linkedin, telegram, email
                FROM users WHERE id = %s
            """, (actor_id,))
            user = cur.fetchone()

            if user:
                city, state_code, country_code = user[3], user[4], user[5]
                filtered_states = [s for s in states if s["country_code"] == country_code]
                state_code_to_name = {s["state_code"]: s["name"] for s in filtered_states}
                readable_country = iso_to_country.get(country_code, country_code)
                readable_state = state_code_to_name.get(state_code, state_code)
                location_display = ", ".join(filter(None, [city, readable_state, readable_country]))

                actor_details[actor_id] = {
                    "user_id": actor_id,
                    "full_name": f"{user[0]} {user[1]}",
                    "role": user[2],
                    "city": city,
                    "state": state_code,
                    "country": country_code,
                    "location_display": location_display,
                    "profile_pic": user[6],
                    "cover_photo": user[7],
                    "skills": user[8],
                    "preferences": user[9],
                    "experience_level": user[10],
                    "facebook": user[11],
                    "instagram": user[12],
                    "x": user[13],
                    "linkedin": user[14],
                    "telegram": user[15],
                    "email": user[16]
                }

        # 5. Friend Requests
        cur.execute("""
            SELECT fr.request_id, fr.sender_id, u.first_name, u.last_name, fr.created_at
            FROM friend_requests fr
            JOIN users u ON fr.sender_id = u.id
            WHERE fr.receiver_id = %s AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
        """, (user_id,))
        requests = cur.fetchall()

        # 6. Get current user's profile_pic
        cur.execute("SELECT profile_pic FROM users WHERE id = %s", (user_id,))
        result = cur.fetchone()
        profile_pic_url = url_for('profile_pics', filename=result[0]) if result and result[0] and result[0] != 'pfp.jpg' else url_for('static', filename='pfp.jpg')

    finally:
        cur.close()
        conn.close()

    return render_template('saved.html',
        user=current_user,
        saved_posts=saved_posts,
        comments=all_comments,
        likes_data=likes_data,
        comment_likes_data=comment_likes_data,
        notifications=notifications,
        requests=requests,
        verified=current_user.verified,
        comments_by_image=all_comments,
        profile_pic_url=profile_pic_url,
        actor_details=actor_details
    )

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

    return jsonify({'status': 'saved'})


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

    return jsonify({'status': 'unsaved'})

def delete_account(user_id):
    try:
        conn = psycopg2.connect(
            host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
            dbname="ocularis_db", 
            user="ocularis_db_user", 
            password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
            port=5432
        )
        conn.autocommit = True
        cur = conn.cursor()

        # Delete user by ID
        cur.execute("DELETE FROM users WHERE id = %s;", (user_id,))
        print(f"User {user_id} deleted successfully.")

        cur.close()
        conn.close()
        
    except Exception as e:
        print("Error deleting account:", e)

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account_route():
    try:
        delete_account(current_user.id)
        session.clear()
        logout_user()
        flash('Your account has been deleted.', 'success')
        return redirect(url_for('login'))
    except Exception as e:
        app.logger.error(f"Error deleting account: {e}")
        flash('An error occurred while deleting your account.', 'danger')
        return redirect(url_for('settings'))

@app.route('/search')
@login_required
def search_results():
    query = request.args.get('query', '').strip()
    like_query = f"%{query}%"
    user_id = current_user.id

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    try:
        # 🔍 Search images
        cur.execute("""
            SELECT 
                images.image_id,
                images.image_url,
                images.caption,
                COALESCE(like_count, 0),
                images.id,
                author.first_name,
                author.last_name,
                images.created_at,
                collaborator.id,
                collaborator.first_name,
                collaborator.last_name,
                author.profile_pic,
                collaborator.profile_pic,
                EXISTS (
                    SELECT 1 FROM likes 
                    WHERE user_id = %s AND image_id = images.image_id
                ) AS is_liked
            FROM images
            JOIN users AS author ON images.id = author.id
            LEFT JOIN users AS collaborator ON images.collaborator_id = collaborator.id
            LEFT JOIN (
                SELECT image_id, COUNT(*) AS like_count 
                FROM likes 
                GROUP BY image_id
            ) AS likes ON images.image_id = likes.image_id
            LEFT JOIN image_tags ON images.image_id = image_tags.image_id
            LEFT JOIN hidden_posts hp ON images.image_id = hp.image_id AND hp.user_id = %s
            WHERE hp.user_id IS NULL
              AND (
                    images.caption ILIKE %s OR
                    image_tags.tag ILIKE %s OR
                    (author.first_name || ' ' || author.last_name) ILIKE %s OR
                    (collaborator.first_name || ' ' || collaborator.last_name) ILIKE %s
                  )
            ORDER BY images.created_at DESC
        """, (user_id, user_id, like_query, like_query, like_query, like_query))
        images = cur.fetchall()

        # 🗨️ Comments
        image_ids = tuple([img[0] for img in images])
        comments = []

        if image_ids:
            cur.execute("""
                SELECT 
                    comments.comment_id,                                      -- 0
                    comments.image_id,                                        -- 1
                    users.first_name || ' ' || users.last_name AS display_name,  -- 2
                    comments.comment_text,                                    -- 3
                    comments.created_at,                                      -- 4
                    COALESCE(cl.like_count, 0),                               -- 5
                    comments.user_id,                                         -- 6
                    users.profile_pic,                                        -- 7
                    EXISTS (                                                  -- 8 ✅ is_liked
                        SELECT 1 FROM comment_likes 
                        WHERE comment_likes.comment_id = comments.comment_id 
                        AND comment_likes.user_id = %s
                    ) AS is_liked
                FROM comments
                JOIN users ON comments.user_id = users.id
                LEFT JOIN (
                    SELECT comment_id, COUNT(*) AS like_count
                    FROM comment_likes
                    GROUP BY comment_id
                ) AS cl ON comments.comment_id = cl.comment_id
                WHERE comments.image_id IN %s
                ORDER BY comments.created_at ASC
            """, (user_id, image_ids))  # Make sure user_id is defined before this
            comments = cur.fetchall()

        # 👍 Image Likes
        likes_data = {}
        for image in images:
            image_id = image[0]
            cur.execute("""
                SELECT u.first_name || ' ' || u.last_name, l.created_at
                FROM likes l
                JOIN users u ON l.user_id = u.id
                WHERE l.image_id = %s
                ORDER BY l.created_at DESC
            """, (image_id,))
            likes_data[image_id] = cur.fetchall()

        # ❤️ Comment Likes
        comment_likes_data = {}
        for comment in comments:
            comment_id = comment[0]
            cur.execute("""
                SELECT u.first_name || ' ' || u.last_name, cl.created_at
                FROM comment_likes cl
                JOIN users u ON cl.user_id = u.id
                WHERE cl.comment_id = %s
                ORDER BY cl.created_at DESC
            """, (comment_id,))
            comment_likes_data[comment_id] = cur.fetchall()

        # 💾 Saved images
        cur.execute("SELECT image_id FROM saved_posts WHERE user_id = %s", (user_id,))
        saved_image_ids = [row[0] for row in cur.fetchall()]

        # 👤 Current user PFP
        cur.execute("SELECT profile_pic FROM users WHERE id = %s", (user_id,))
        result = cur.fetchone()
        profile_pic_url = url_for('profile_pics', filename=result[0]) if result and result[0] and result[0] != 'pfp.jpg' else url_for('static', filename='pfp.jpg')

        # 🧑‍🤝‍🧑 User search
        cur.execute("""
            SELECT id, first_name, last_name, profile_pic, verified
            FROM users
            WHERE (LOWER(first_name) LIKE LOWER(%s)
                OR LOWER(last_name) LIKE LOWER(%s)
                OR LOWER(first_name || ' ' || last_name) LIKE LOWER(%s))
        """, (like_query, like_query, like_query))
        users_raw = cur.fetchall()

        users = []
        for u in users_raw:
            uid, fname, lname, pfp, verified = u

            if uid == current_user.id:
                relationship = 'self'
                request_id = None
            else:
                cur.execute("""
                    SELECT sender_id, receiver_id, status, request_id
                    FROM friend_requests
                    WHERE (sender_id = %s AND receiver_id = %s)
                       OR (sender_id = %s AND receiver_id = %s)
                    LIMIT 1
                """, (user_id, uid, uid, user_id))
                row = cur.fetchone()

                relationship = 'not_friends'
                request_id = None
                if row:
                    sender, receiver, status, req_id = row
                    request_id = req_id
                    if status == 'accepted':
                        relationship = 'friends'
                    elif status == 'pending':
                        if receiver == user_id:
                            relationship = 'incoming_pending'
                        else:
                            relationship = 'outgoing_pending'
                    elif status == 'rejected':
                        relationship = 'outgoing_rejected'

            users.append({
                'id': uid,
                'name': f"{fname} {lname}",
                'profile_pic': url_for('profile_pics', filename=pfp) if pfp and pfp != 'pfp.jpg' else url_for('static', filename='pfp.jpg'),
                'verified': verified,
                'relationship': relationship,
                'request_id': request_id
            })
            
                        # Fetch notifications
        cur.execute("""
            SELECT                 
                users.first_name || ' ' || users.last_name AS display_name,
                notifications.action_type,
                notifications.image_id,
                notifications.created_at,
                notifications.actor_id,
                users.profile_pic,
                notifications.notification_id
            FROM notifications
            JOIN users ON notifications.actor_id = users.id
            WHERE notifications.recipient_id = %s
            ORDER BY notifications.created_at DESC
        """, (current_user.id,))
        notifications = cur.fetchall()
        
                        # Gather unique actor_ids
        actor_ids = list(set([n[4] for n in notifications]))

            # Prepare dictionary to hold actor_id → user profile details
        actor_details = {}

            # Fetch full details for each actor_id
        for actor_id in actor_ids:
            cur.execute("""
                SELECT first_name, last_name, role, city, state, country, 
                    profile_pic, cover_photo, skills, preferences, experience_level,
                    facebook, instagram, x, linkedin, telegram, email
                FROM users WHERE id = %s
            """, (actor_id,))
            user = cur.fetchone()
            
            if user:
                countries = current_app.config['COUNTRIES']
                states = current_app.config['STATES']

                # Get raw codes
                city = user[3]
                state_code = user[4]
                country_code = user[5]

                # Look up readable names
                iso_to_country = {c["iso2"]: c["name"] for c in countries}
                readable_country = iso_to_country.get(country_code, country_code)

                # Filter states by selected country
                filtered_states = [s for s in states if s["country_code"] == country_code]
                state_code_to_name = {s["state_code"]: s["name"] for s in filtered_states}
                readable_state = state_code_to_name.get(state_code, state_code)

                # Display-friendly location string
                location_display = ", ".join(filter(None, [city, readable_state, readable_country]))

                actor_details[actor_id] = {
                    "user_id": actor_id,
                    "full_name": f"{user[0]} {user[1]}",
                    "role": user[2],
                    "city": city,
                    "state": state_code,
                    "country": country_code,
                    "location_display": location_display,  # ✅ new key
                    "profile_pic": user[6],
                    "cover_photo": user[7],
                    "skills": user[8],
                    "preferences": user[9],
                    "experience_level": user[10],
                    "facebook": user[11],
                    "instagram": user[12],
                    "x": user[13],
                    "linkedin": user[14],
                    "telegram": user[15],
                    "email": user[16]
                }
        
                # Fetch friend requests
        cur.execute("""
            SELECT fr.request_id, fr.sender_id, u.first_name, u.last_name, fr.created_at
            FROM friend_requests fr
            JOIN users u ON fr.sender_id = u.id
            WHERE fr.receiver_id = %s AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
        """, (current_user.id,))
        requests = cur.fetchall()    

        return render_template("results.html", 
                               query=query,
                               images=images, 
                               comments=comments,
                               likes_data=likes_data,
                               comment_likes_data=comment_likes_data,
                               saved_image_ids=saved_image_ids,
                               profile_pic_url=profile_pic_url,
                               users=users,
                               user=current_user,
                               notifications=notifications,
                               actor_details=actor_details,
                               requests=requests)

    finally:
        cur.close()
        conn.close()

@app.route('/report', methods=['POST'])
@login_required
def report():
    image_id = request.form.get('image_id')
    reasons = request.form.getlist('reason')

    if not image_id or not reasons:
        return jsonify({'status': 'error', 'message': 'Missing data'}), 400

    try:
        conn = psycopg2.connect(
            host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
            dbname="ocularis_db", 
            user="ocularis_db_user", 
            password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
            port=5432
        )
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO reports (image_id, user_id, reasons, timestamp)
            VALUES (%s, %s, %s, NOW())
        """, (image_id, current_user.id, ', '.join(reasons)))

        cur.execute("""
            INSERT INTO hidden_posts (user_id, image_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
        """, (current_user.id, image_id))

        conn.commit()
        return jsonify({'status': 'success', 'message': 'Report submitted and post hidden'})
    except Exception as e:
        app.logger.error(f"Report error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()
        
@app.route('/update-notifications', methods=['POST'])
@login_required
def update_notifications():
    notify_likes = 'notify_likes' in request.form
    notify_comments = 'notify_comments' in request.form
    notify_requests = 'notify_requests' in request.form

    # Open the connection
    conn = None
    try:
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
            SET notify_likes = %s,
                notify_comments = %s,
                notify_requests = %s
            WHERE id = %s
        """, (notify_likes, notify_comments, notify_requests, current_user.id))

        conn.commit()
        cur.close()
    except Exception as e:
        print("Error updating notification preferences:", e)
        if conn:
            conn.rollback()
        flash("Failed to update notification preferences.", "error")
    finally:
        if conn:
            conn.close()

    flash("Notification preferences updated.")
    return redirect(url_for('settings'))

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not current_password or not new_password or not confirm_password:
        flash('Please fill out all password fields.', 'error')
        return redirect(url_for('settings'))

    if new_password != confirm_password:
        flash('New password and confirm password do not match.', 'error')
        return redirect(url_for('settings'))

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    # Check current password
    cur.execute("SELECT password FROM users WHERE id = %s", (current_user.id,))
    result = cur.fetchone()
    if not result or not check_password_hash(result[0], current_password):
        flash('Current password is incorrect.', 'error')
        cur.close()
        conn.close()
        return redirect(url_for('settings'))

    # Update password
    hashed_new_password = generate_password_hash(new_password)
    cur.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_new_password, current_user.id))
    conn.commit()
    cur.close()
    conn.close()

    flash('Password changed successfully.', 'success')
    return redirect(url_for('settings'))

@app.route("/lock_match_route", methods=["POST"])
@login_required
def lock_match_route():
    user_id = current_user.id
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
                INSERT INTO collab_actions (user_id) VALUES (%s)
            """, (user_id,))
    return '', 204

if __name__ == '__main__':
    app.run(debug=True)