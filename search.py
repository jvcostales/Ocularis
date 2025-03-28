from flask import Blueprint, request, render_template
import psycopg2

# Create a Flask Blueprint for search
search_bp = Blueprint('search', __name__)

# Connect to PostgreSQL
conn = psycopg2.connect(host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", dbname="ocularis_db", user="ocularis_db_user", password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", port=5432)
cur = conn.cursor()

@search_bp.route('/search')
def search_results():
    query = request.args.get('query', '')

    # Search users by first name or last name
    cur.execute("SELECT id, first_name, last_name FROM users WHERE first_name ILIKE %s OR last_name ILIKE %s",
                (f"%{query}%", f"%{query}%"))
    users = cur.fetchall()

    # Search posts by caption and tags
    cur.execute("""
        SELECT images.image_id, images.image_url, images.caption
        FROM images
        LEFT JOIN image_tags ON images.image_id = image_tags.image_id
        WHERE images.caption ILIKE %s OR image_tags.tag ILIKE %s
    """, (f"%{query}%", f"%{query}%"))
    posts = cur.fetchall()

    return render_template("results.html", query=query, users=users, posts=posts)