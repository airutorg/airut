// SSE-to-polling fallback coordination
//
// State-based pages (dashboard, task detail, repo detail): reload the page
// on SSE failure so the server re-renders fresh HTML.
//
// Append-only pages (actions, network): poll dedicated JSON endpoints that
// return {offset, html, done} and append new content.
(function() {
    var MAX_FAILURES = 3;
    var POLL_INTERVAL = 3000;
    var RELOAD_INTERVAL = 5000;
    var failureCount = 0;
    var polling = false;

    function startPolling(container) {
        if (polling) return;
        polling = true;

        // Append-only pages embed a data-poll-url on the container
        var pollUrl = container.getAttribute('data-poll-url');
        if (pollUrl) {
            pollAppendOnly(container, pollUrl);
        } else {
            // State-based page: reload periodically
            setInterval(function() {
                window.location.reload();
            }, RELOAD_INTERVAL);
        }
    }

    function pollAppendOnly(container, baseUrl) {
        var offset = parseInt(container.getAttribute('data-poll-offset') || '0', 10);

        function poll() {
            var url = baseUrl + '?offset=' + offset;
            fetch(url, {headers: {'If-None-Match': '"o' + offset + '"'}})
                .then(function(resp) {
                    if (resp.status === 304) return null;
                    return resp.json();
                })
                .then(function(data) {
                    if (!data) return;
                    if (data.html) {
                        container.insertAdjacentHTML('beforeend', data.html);
                    }
                    if (data.offset !== undefined) {
                        offset = data.offset;
                        container.setAttribute('data-poll-offset', String(offset));
                    }
                    if (data.done) {
                        var status = document.getElementById('stream-status');
                        if (status) status.textContent = 'Complete';
                        return;
                    }
                    setTimeout(poll, POLL_INTERVAL);
                })
                .catch(function() {
                    setTimeout(poll, POLL_INTERVAL);
                });
        }

        poll();
    }

    document.addEventListener('htmx:sseError', function(evt) {
        failureCount++;
        if (failureCount >= MAX_FAILURES) {
            var sseContainer = evt.target.closest('[hx-ext="sse"]');
            if (!sseContainer) return;
            var status = document.getElementById('stream-status');
            if (status) status.textContent = 'Polling';
            startPolling(sseContainer);
        }
    });

    document.addEventListener('htmx:sseOpen', function() {
        failureCount = 0;
        var status = document.getElementById('stream-status');
        if (status) status.textContent = 'Live';
    });
})();
