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

function renderLikes(likes, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (likes.length === 0) {
        container.innerHTML = "<em>No likes yet.</em>";
        return;
    }

    const html = likes.map(like => {
        const dateObj = new Date(like.created_at);
        const month = dateObj.toLocaleString('en-US', { month: 'short' });
        const day = dateObj.getDate();

        return `
            <div class="profile-follow-wrapper">
                <div class="profile-post-likes">
                    <img src="../static/pfp.jpg" class="pfp" />
                    <div class="profile-name-date">
                        <div class="username">${like.display_name}</div>
                        <div class="date">${month} ${day}</div>
                    </div>
                </div>
                <button class="follow-button">Befriend</button>
            </div>
        `;
    }).join('');

    container.innerHTML = html;
}

function fetchLikes(imageId, index) {
    fetch(`/likes/${imageId}`)
        .then(response => response.json())
        .then(data => {
            renderLikes(data.likes, `likesList-${index}`);
        })
        .catch(error => {
            console.error("Error fetching likes:", error);
        });
}