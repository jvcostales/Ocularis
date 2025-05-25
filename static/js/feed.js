function likeImage(imageId, index) {
    fetch(`/like/${imageId}`, {
        method: 'POST',
        body: JSON.stringify({}),
        headers: {
            'Content-Type': 'application/json'
        },
        credentials: 'include'
    })
        .then(response => response.json())
        .then(data => {
            document.getElementById(`like-count-${index}`).textContent = data.like_count;
            const button = document.querySelector(`#openOverlayLikes-${index}`).previousElementSibling;
            button.style.color = data.liked ? 'blue' : '';
        })
        .catch(err => console.error('Like error:', err));
}

function loadLikes(imageId) {
    fetch(`/get_likes/${imageId}`)
        .then(response => response.json())
        .then(data => {
            const container = document.getElementById(`likes-container-${imageId}`);
            container.innerHTML = '';  // Clear old content

            if (data.length === 0) {
                container.innerHTML = `
                    <div class="likes-empty">
                        <span class="material-symbols-outlined empty-symbol">sentiment_dissatisfied</span>
                        <div class="oops">Oops!</div>
                        <div class="nothing">Nothing to show here at the moment.</div>
                    </div>
                `;
                return;
            }

            data.forEach(like => {
                container.innerHTML += `
                    <div class="profile-follow-wrapper">
                        <div class="profile-post-likes">
                            <img src="..\\static\\pfp.jpg" class="pfp">
                            <div class="profile-name-date">
                                <div class="username">${like.display_name}</div>
                                <div class="date">${like.created_at}</div>
                            </div>
                        </div>
                        <button class="follow-button">Befriend</button>
                    </div>
                `;
            });
        });
}

function toggleLike(imageId) {
    fetch(`/like/${imageId}`, {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        // Update like count UI (if you show a number somewhere)
        const countEl = document.getElementById(`like-count-${imageId}`);
        if (countEl) {
            countEl.textContent = `${data.like_count} ${data.like_count === 1 ? 'like' : 'likes'}`;
        }

        // Update button state (optional)
        const btn = document.getElementById(`like-button-${imageId}`);
        if (btn) {
            if (data.liked) {
                btn.textContent = "Unlike";
                btn.classList.add("liked");
            } else {
                btn.textContent = "Like";
                btn.classList.remove("liked");
            }
        }

        // Now update the likes list
        loadLikes(imageId);
    });
}