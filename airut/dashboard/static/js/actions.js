// Collapsible JSON blocks in actions viewer - event delegation
document.addEventListener('click', function(e) {
    var header = e.target.closest('.event-header');
    if (!header) return;
    var body = header.parentElement.querySelector('.event-body');
    var icon = header.querySelector('.toggle-icon');
    if (!body || !icon) return;
    if (body.classList.contains('expanded')) {
        body.classList.remove('expanded');
        icon.textContent = '+';
    } else {
        body.classList.add('expanded');
        icon.textContent = '-';
    }
});
