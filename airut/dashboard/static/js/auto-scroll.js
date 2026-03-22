// Auto-scroll for append-only pages (actions, network).
//
// The htmx SSE extension fires htmx:sseMessage (not htmx:afterSwap)
// after swapping content into the DOM.  We listen for that event on
// the document and scroll to the bottom when the user hasn't scrolled
// up manually.
//
// We guard programmatic scrollTo calls so they don't re-trigger the
// scroll listener with intermediate positions (which can falsely
// disable auto-scroll on iOS, especially iPad).
(function() {
    var autoScroll = true;
    var scrolling = false;

    function docHeight() {
        return document.documentElement.scrollHeight;
    }

    function scrollToBottom() {
        scrolling = true;
        window.scrollTo(0, docHeight());
        requestAnimationFrame(function() { scrolling = false; });
    }

    // Scroll to bottom on initial load
    scrollToBottom();

    // Track if user has scrolled up (disable auto-scroll).
    // Ignore scroll events caused by our own scrollTo calls.
    window.addEventListener('scroll', function() {
        if (scrolling) return;
        autoScroll = (
            window.innerHeight + window.scrollY
            >= docHeight() - 100
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
})();
