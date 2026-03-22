// Auto-scroll for append-only pages (actions, network).
//
// The htmx SSE extension's swap bypasses htmx:afterSwap and
// htmx:sseMessage doesn't reliably fire after the DOM update.
// Instead, we use a MutationObserver to detect new children
// appended to the container and scroll to the bottom.
(function() {
    var autoScroll = true;

    // Scroll to bottom on initial load
    window.scrollTo(0, document.body.scrollHeight);

    // Track if user has scrolled up (disable auto-scroll)
    window.addEventListener('scroll', function() {
        var nearBottom = (
            window.innerHeight + window.scrollY
            >= document.body.offsetHeight - 100
        );
        autoScroll = nearBottom;
    });

    // Observe the container for new child elements added by SSE swap.
    var container =
        document.getElementById('events-container') ||
        document.getElementById('logs-container');

    if (container) {
        var observer = new MutationObserver(function() {
            if (autoScroll) {
                window.scrollTo(0, document.body.scrollHeight);
            }
        });
        observer.observe(container, { childList: true });
    }
})();
