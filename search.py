from flask import Blueprint, request, render_template
import psycopg2

# Create a Flask Blueprint for search
search_bp = Blueprint('search', __name__)


@search_bp.route('/search')
def search_results():
    query = request.args.get('query', '')

    conn = psycopg2.connect(
        host="dpg-cuk76rlumphs73bb4td0-a.oregon-postgres.render.com", 
        dbname="ocularis_db", 
        user="ocularis_db_user", 
        password="ZMoBB0Iw1QOv8OwaCuFFIT0KRTw3HBoY", 
        port=5432
    )
    cur = conn.cursor()

    try:
        # Search for users by first or last name
        cur.execute("""
            SELECT id, first_name, last_name 
            FROM users 
            WHERE first_name ILIKE %s OR last_name ILIKE %s
        """, (f"%{query}%", f"%{query}%"))
        users = cur.fetchall()

        # Search for images by caption or tag
        cur.execute("""
            SELECT DISTINCT ON (images.image_id)
                images.image_id, images.image_url, images.caption, 
                COALESCE(likes.like_count, 0), users.id AS user_id, 
                users.first_name, users.last_name
            FROM images 
            JOIN users ON images.id = users.id
            LEFT JOIN (
                SELECT image_id, COUNT(*) AS like_count 
                FROM likes 
                GROUP BY image_id
            ) AS likes ON images.image_id = likes.image_id
            LEFT JOIN image_tags ON images.image_id = image_tags.image_id
            WHERE images.caption ILIKE %s OR image_tags.tag ILIKE %s
            ORDER BY images.image_id
        """, (f"%{query}%", f"%{query}%"))
        images = cur.fetchall()

        # Fetch comments **only for images that matched the search**
        image_ids = tuple(img[0] for img in images)  # Extract image IDs from search results

        comments = []
        if image_ids:  # Only run query if there are matching images
            cur.execute(f"""
                SELECT comments.comment_id, comments.image_id, 
                    users.first_name || ' ' || users.last_name AS display_name, 
                    comments.comment_text, comments.created_at,
                    COALESCE(cl.like_count, 0) AS like_count, comments.user_id
                FROM comments
                JOIN users ON comments.user_id = users.id
                LEFT JOIN (
                    SELECT comment_id, COUNT(*) AS like_count
                    FROM comment_likes
                    GROUP BY comment_id
                ) AS cl ON comments.comment_id = cl.comment_id
                WHERE comments.image_id IN %s
                ORDER BY comments.created_at ASC
            """, (image_ids,))
            comments = cur.fetchall()

        return render_template("results.html", query=query, users=users, images=images, comments=comments)

    finally:
        cur.close()
        conn.close()