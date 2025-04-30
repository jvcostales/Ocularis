from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, flash, jsonify
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
import pandas as pd
import json

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
    country TEXT NOT NULL,
    state TEXT NOT NULL,
    city TEXT NOT NULL,
    role VARCHAR(100) NOT NULL,
    facebook VARCHAR(100),
    instagram VARCHAR(100),
    x VARCHAR(100),
    linkedin VARCHAR(100),
    telegram VARCHAR(100),
    is_profile_complete BOOLEAN DEFAULT FALSE
);
""")

cur.execute(""" 
CREATE TABLE IF NOT EXISTS images (
    image_id SERIAL PRIMARY KEY,
    id INT NOT NULL,
    image_url VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (id) REFERENCES users(id) ON DELETE CASCADE,
    caption TEXT
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

conn.commit()

cur.close()
conn.close()

class User(UserMixin):
    def __init__(self, id, first_name, last_name, email, password):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
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
        return User(id=user[0], first_name=user[1], last_name=user[2], email=user[3], password=user[4])
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

            # New logic: Check if profile is incomplete
            skills = user[8]  # Assuming skills is at index 8
            preferences = user[9]  # Preferences at index 9
            experience_level = user[10]  # Experience level at index 10

            if not skills or not preferences or experience_level is None:
                return redirect(url_for('setup_profile'))

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
                telegram = %s
            WHERE id = %s
        """, (skills, prefs, level, role, facebook, instagram, x, linkedin, telegram, current_user.id))
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({'success': True})



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
    tags = [
        "Architecture", "Art Direction", "Branding", "Fashion", "Graphic Design",
        "Illustration", "Industrial Design", "Interaction Design", "Logo Design",
        "Motion Graphics", "Photography", "UI/UX", "Web Design"
    ]

    if request.method == 'POST':
        if 'image' not in request.files:
            return 'No file part'
        
        file = request.files['image']
        caption = request.form.get('caption', '')
        selected_tags = request.form.getlist('tags')
        
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
        cur.execute("""
            SELECT images.image_id, images.image_url, images.caption,
                   COALESCE(like_count, 0), images.id, users.first_name, users.last_name
            FROM images 
            JOIN users ON images.id = users.id
            LEFT JOIN (
                SELECT image_id, COUNT(*) AS like_count 
                FROM likes 
                GROUP BY image_id
            ) AS likes 
            ON images.image_id = likes.image_id
            ORDER BY images.created_at DESC
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
            SELECT users.first_name || ' ' || users.last_name AS display_name,
                   notifications.action_type, notifications.image_id, notifications.created_at
            FROM notifications
            JOIN users ON notifications.actor_id = users.id
            WHERE notifications.recipient_id = %s
            ORDER BY notifications.created_at DESC
        """, (current_user.id,))
        notifications = cur.fetchall()

        # Fetch friend requests
        cur.execute("""
            SELECT fr.request_id, u.first_name, u.last_name, fr.created_at
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

    return render_template(
        'feed.html',
        tags=tags,
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
        cities=app.config['CITIES']
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
    cur.execute("SELECT first_name, last_name FROM users WHERE id = %s", (user_id,))
    user = cur.fetchone()

    # Fetch user's posts
    cur.execute("""
        SELECT images.image_id, images.image_url, images.caption, 
               (SELECT COUNT(*) FROM likes WHERE likes.image_id = images.image_id) AS like_count,
               images.id, users.first_name, users.last_name
        FROM images
        JOIN users ON images.id = users.id
        WHERE images.id = %s
        ORDER BY images.created_at DESC
    """, (user_id,))
    images = cur.fetchall()

    # Fetch comments on the user's posts
    cur.execute("""
        SELECT comments.comment_id, comments.image_id, users.first_name, 
               comments.comment_text, comments.created_at, 
               (SELECT COUNT(*) FROM comment_likes WHERE comment_likes.comment_id = comments.comment_id) AS like_count,
               comments.user_id
        FROM comments
        JOIN users ON comments.user_id = users.id
        WHERE comments.image_id IN (SELECT image_id FROM images WHERE id = %s)
        ORDER BY comments.created_at ASC
    """, (user_id,))
    comments = cur.fetchall()

    # Check friend status
    cur.execute("""
        SELECT 1 FROM friends 
        WHERE (user1_id = %s AND user2_id = %s)
            OR (user1_id = %s AND user2_id = %s);
    """, (current_user_id, user_id, user_id, current_user_id))
    is_friend = cur.fetchone() is not None

    # Check if a friend request is already sent
    cur.execute("""
        SELECT status FROM friend_requests
        WHERE sender_id = %s AND receiver_id = %s;
    """, (current_user_id, user_id))
    request_status = cur.fetchone()

    cur.close()
    conn.close()

    # Add a flag to indicate if the "Add Friend" button should be disabled
    disable_add_friend = is_friend or current_user_id == user_id

    return render_template(
        "profile.html",
        user=user,
        images=images,
        comments=comments,
        user_id=user_id,
        is_friend=is_friend,
        request_status=request_status,
        is_own_profile=(current_user_id == user_id),
        disable_add_friend=disable_add_friend  # Passing the flag to the template
    )

@app.route('/send_request/<int:receiver_id>', methods=['GET'])
@login_required
def send_request(receiver_id):
    sender_id = current_user.id

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
        # Prevent sending a request if already friends
        cur.execute("""
            SELECT * FROM friends
            WHERE (user1_id = %s AND user2_id = %s)
               OR (user1_id = %s AND user2_id = %s);
        """, (sender_id, receiver_id, receiver_id, sender_id))
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


@app.route('/accept_request/<int:request_id>')
def accept_request(request_id):
    receiver_id = current_user.id
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()

    # Fetch sender from request
    cur.execute("""
        SELECT sender_id FROM friend_requests 
        WHERE request_id = %s AND receiver_id = %s AND status = 'pending';
    """, (request_id, receiver_id))
    row = cur.fetchone()
    if not row:
        flash("Request not found.")
        return redirect('/requests')
    
    sender_id = row[0]

    # Update request status
    cur.execute("""
        UPDATE friend_requests SET status = 'accepted'
        WHERE request_id = %s;
    """, (request_id,))

    # Add to friends
    cur.execute("""
        INSERT INTO friends (user1_id, user2_id) VALUES (%s, %s);
    """, (min(sender_id, receiver_id), max(sender_id, receiver_id)))

    conn.commit()
    cur.close()
    conn.close()
    flash("Friend request accepted.")
    return redirect('/feed')


@app.route('/reject_request/<int:request_id>')
def reject_request(request_id):
    receiver_id = current_user.id
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()

    cur.execute("""
        UPDATE friend_requests 
        SET status = 'rejected' 
        WHERE request_id = %s AND receiver_id = %s AND status = 'pending';
    """, (request_id, receiver_id))

    conn.commit()
    cur.close()
    conn.close()
    flash("Friend request rejected.")
    return redirect('/feed')

@app.route('/recommendations', methods=['GET'])
@login_required
def recommendations():
    # Fetch all users from DB
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()
    cur.execute("SELECT id, skills, preferences, experience_level FROM users")
    rows = cur.fetchall()
    cur.close()
    conn.close()

    # Convert to DataFrame format for the recommender
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

    # Skip if user hasn't set up their profile yet
    if current_user.id not in df["user"].values:
        return "Please complete your profile to get recommendations."

    # Get index of current user
    target_index = df[df['user'] == current_user.id].index[0]
    similar_users_df = get_similar_users(target_index, df)

    if similar_users_df.empty:
        return render_template("recommendations.html", users=[])

    # Fetch names for recommended users
    user_ids = similar_users_df['user'].tolist()
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()
    cur.execute("SELECT id, first_name, last_name FROM users WHERE id = ANY(%s)", (user_ids,))
    name_rows = cur.fetchall()
    cur.close()
    conn.close()

    # Map ID → Full Name
    name_map = {row[0]: f"{row[1]} {row[2]}" for row in name_rows}

    # Attach names to each user dict
    users_list = []
    for user in similar_users_df.to_dict(orient='records'):
        user["name"] = name_map.get(user["user"], "Unknown")
        users_list.append(user)

    return render_template("recommendations.html", users=users_list)

if __name__ == '__main__':
    app.run(debug=True)