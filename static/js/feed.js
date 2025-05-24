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