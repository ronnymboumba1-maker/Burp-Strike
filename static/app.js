// Auto-refresh du badge pending
setInterval(async () => {
    try {
        const r = await fetch('/api/stats');
        const s = await r.json();
        const badge = document.getElementById('pending-badge');
        if (badge) {
            if (s.pending > 0) {
                badge.textContent = s.pending;
                badge.style.display = 'inline-block';
            } else {
                badge.style.display = 'none';
            }
        }
    } catch (e) {}
}, 2000);