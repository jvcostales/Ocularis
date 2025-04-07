from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import psycopg2
from werkzeug.utils import secure_filename
import os
import smtplib
import secrets
from email.mime.text import MIMEText
from search import search_bp

app = Flask(__name__)
app.secret_key = 'v$2nG#8mKqT3@z!bW7e^d6rY*9xU&j!P'
app.register_blueprint(search_bp)
login_manager = LoginManager()
login_manager.init_app(app)

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
    reset_token TEXT
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

        conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", dbname="ocularis_db", user="ocularis_db_user", password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", port=5432)
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user[4], password):  # password is now at index 4
            login_user(User(id=user[0], first_name=user[1], last_name=user[2], email=user[3], password=user[4]))
            return redirect(url_for('feed'))
        else:
            return 'Invalid email or password'
    return render_template('login.html')

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

@app.route('/feed')
@login_required
def feed():
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()
    
    try:
        # Fetch images with their captions and like counts
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

        # Fetch comments and display name (first + last)
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
    tags = [
        "Architecture", "Art Direction", "Branding", "Fashion", "Graphic Design",
        "Illustration", "Industrial Design", "Interaction Design", "Logo Design",
        "Motion Graphics", "Photography", "UI/UX", "Web Design"
    ]

    if request.method == 'POST':
        if 'image' not in request.files:
            return 'No file part'
        
        file = request.files['image']
        caption = request.form.get('caption', '')  # Get the caption, default to empty string
        selected_tags = request.form.getlist('tags')  # Get selected tags as a list
        
        if file.filename == '':
            return 'No selected file'
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join('/var/data', filename)
            file.save(file_path)    

            image_url = f"https://ocular-zmcu.onrender.com/images/{filename}"

            conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
                                    dbname="ocularis_db", 
                                    user="ocularis_db_user", 
                                    password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
                                    port=5432)
            cur = conn.cursor()

            # Insert image into images table
            cur.execute("INSERT INTO images (id, image_url, caption) VALUES (%s, %s, %s) RETURNING id", 
                        (current_user.id, image_url, caption))
            image_id = cur.fetchone()[0]  # Get the inserted image's ID

            # Insert tags into image_tags table
            for tag in selected_tags:
                cur.execute("INSERT INTO image_tags (image_id, tag) VALUES (%s, %s)", (image_id, tag))

            conn.commit()
            cur.close()
            conn.close()

            return redirect(url_for('feed'))

    return render_template('upload.html', tags=tags)

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
            SELECT users.first_name || ' ' || users.last_name AS display_name, notifications.action_type, notifications.image_id, notifications.created_at
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

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    current_user_id = session.get('user_id')
    
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

    return render_template(
        "profile.html",
        user=user,
        images=images,
        comments=comments,
        user_id=user_id,
        is_friend=is_friend,
        request_status=request_status,
        is_own_profile=(current_user_id == user_id)
    )


@app.route('/send_request/<int:receiver_id>', methods=['GET'])
@login_required
def send_request(receiver_id):
    sender_id = current_user.id  # Use current user's ID
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()
    
    # Insert friend request into the database
    cur.execute("""
        INSERT INTO friend_requests (sender_id, receiver_id, status, created_at)
        VALUES (%s, %s, %s, NOW())
    """, (sender_id, receiver_id, 'pending'))
    
    conn.commit()
    cur.close()
    conn.close()

    # Redirect or return some response
    return redirect(url_for('profile', user_id=receiver_id))



@app.route('/accept_request/<int:request_id>')
def accept_request(request_id):
    receiver_id = session.get('user_id')
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
    return redirect('/requests')


@app.route('/reject_request/<int:request_id>')
def reject_request(request_id):
    receiver_id = session.get('user_id')
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
    return redirect('/requests')


@app.route('/requests')
def view_requests():
    user_id = session.get('user_id')
    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com",
        dbname="ocularis_db",
        user="ocularis_db_user",
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY",
        port=5432
    )
    cur = conn.cursor()

    cur.execute("""
        SELECT fr.request_id, u.first_name, u.last_name 
        FROM friend_requests fr
        JOIN users u ON fr.sender_id = u.id
        WHERE fr.receiver_id = %s AND fr.status = 'pending';
    """, (user_id,))
    requests = cur.fetchall()

    cur.close()
    conn.close()
    return render_template('requests.html', requests=requests)

if __name__ == '__main__':
    app.run(debug=True)