// Auto-scroll for append-only pages (actions, network).
//
// Scrolls the .console-page container (not the window) so that the
// navbar stays above the scroll area and iOS address-bar dynamics
// don't interfere with scroll position or sticky positioning.
//
// Content arrives via htmx SSE (htmx:sseMessage) or polling fallback
// (direct DOM insertion).  We handle both: htmx:sseMessage fires for
// SSE swaps, and a MutationObserver catches polling-appended content.
//
// We guard programmatic scroll calls so they don't re-trigger the
// scroll listener with intermediate positions (which can falsely
// disable auto-scroll on iOS, especially iPad).
(function() {
    var scrollEl = document.querySelector('.console-page');
    if (!scrollEl) return;

    var autoScroll = true;
    var scrolling = false;

    function scrollToBottom() {
        scrolling = true;
        scrollEl.scrollTop = scrollEl.scrollHeight;
        requestAnimationFrame(function() { scrolling = false; });
    }

    // Scroll to bottom on initial load
    scrollToBottom();

    // Track if user has scrolled up (disable auto-scroll).
    // Ignore scroll events caused by our own scrollTop assignments.
    scrollEl.addEventListener('scroll', function() {
        if (scrolling) return;
        autoScroll = (
            scrollEl.scrollTop + scrollEl.clientHeight
            >= scrollEl.scrollHeight - 100
        );
    });

    // htmx SSE extension dispatches htmx:sseMessage on the element
    // with sse-swap after the swap completes.
    document.addEventListener('htmx:sseMessage', function(evt) {
        if (autoScroll && evt.target &&
            (evt.target.id === 'events-container' ||
             evt.target.id === 'logs-container')) {
            scrollToBottom();
        }
    });

    // MutationObserver catches content appended by polling fallback
    // (which doesn't fire htmx:sseMessage).
    var container =
        document.getElementById('events-container') ||
        document.getElementById('logs-container');

    if (container) {
        new MutationObserver(function() {
            if (autoScroll) scrollToBottom();
        }).observe(container, { childList: true });
    }
})();
