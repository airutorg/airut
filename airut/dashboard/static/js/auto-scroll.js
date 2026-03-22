// Auto-scroll for append-only pages (actions, network).
//
// The htmx SSE extension fires htmx:sseMessage (not htmx:afterSwap)
// after swapping content into the DOM.  We listen for that event on
// the document and scroll to the bottom when the user hasn't scrolled
// up manually.
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

    // htmx SSE extension dispatches htmx:sseMessage on the element
    // with sse-swap after the swap completes.  evt.target is the
    // element the event was dispatched on (events-container or
    // logs-container).
    document.addEventListener('htmx:sseMessage', function(evt) {
        if (autoScroll && evt.target &&
            (evt.target.id === 'events-container' ||
             evt.target.id === 'logs-container')) {
            window.scrollTo(0, document.body.scrollHeight);
        }
    });
})();
