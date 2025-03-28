from flask import Blueprint, request, render_template
import psycopg2

# Create a Flask Blueprint for search
search_bp = Blueprint('search', __name__)

# Connect to PostgreSQL
conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", dbname="ocularis_db", user="ocularis_db_user", password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", port=5432)
cur = conn.cursor()

@search_bp.route('/search')
def search_results():
    query = request.args.get('query', '').strip()

    cur = conn.cursor()

    # Search users by first name or last name
    cur.execute("""
        SELECT id, first_name, last_name 
        FROM users 
        WHERE first_name ILIKE %s OR last_name ILIKE %s
    """, (f"%{query}%", f"%{query}%"))
    users = cur.fetchall()

    # Search posts by caption or tags, including user info
    cur.execute("""
        SELECT images.image_id, images.image_url, images.caption, 
               images.id AS user_id, users.first_name, users.last_name 
        FROM images
        JOIN users ON images.id = users.id
        LEFT JOIN image_tags ON images.image_id = image_tags.image_id
        WHERE images.caption ILIKE %s OR image_tags.tag ILIKE %s
    """, (f"%{query}%", f"%{query}%"))
    images = cur.fetchall()

    # Search comments related to retrieved images
    image_ids = tuple(img[0] for img in images) if images else (0,)  # Ensure valid query if no images found
    cur.execute("""
        SELECT comments.comment_id, comments.image_id, users.first_name, users.last_name, 
               comments.comment_text, comments.user_id 
        FROM comments 
        JOIN users ON comments.user_id = users.id 
        WHERE comments.image_id IN %s
    """, (image_ids,))
    comments = cur.fetchall()

    cur.close()

    return render_template("results.html", query=query, users=users, images=images, comments=comments)