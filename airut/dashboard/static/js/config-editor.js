/* config-editor.js - Client-side helpers for config editor */

(function() {
  'use strict';

  var dirtyEl = document.getElementById('dirty-count');
  var reviewBtn = document.getElementById('review-save-btn');
  var discardBtn = document.getElementById('discard-btn');

  function updateDirtyDisplay(count) {
    if (dirtyEl) {
      if (count > 0) {
        dirtyEl.textContent = count + ' unsaved change' + (count !== 1 ? 's' : '');
        dirtyEl.classList.remove('hidden');
      } else {
        dirtyEl.textContent = '';
        dirtyEl.classList.add('hidden');
      }
    }
    // Enable/disable save bar buttons based on dirty count.
    if (reviewBtn) reviewBtn.disabled = count === 0;
    if (discardBtn) discardBtn.disabled = count === 0;
  }

  // Read server-reported dirty count from mutation responses.
  // The server computes the actual diff (buffer vs live config) so
  // reverting a field back to its original value gives count 0.
  document.body.addEventListener('htmx:afterRequest', function(evt) {
    var xhr = evt.detail.xhr;
    var dirtyHeader = xhr && xhr.getResponseHeader('X-Dirty-Count');
    if (dirtyHeader !== null) {
      updateDirtyDisplay(parseInt(dirtyHeader, 10) || 0);
    }

    // Reset on save or discard
    var path = evt.detail.pathInfo && evt.detail.pathInfo.requestPath;
    if (path && (path.endsWith('/save') || path.endsWith('/discard')) &&
        evt.detail.successful) {
      updateDirtyDisplay(0);
    }
  });

  // htmx 2.x does not swap 4xx/5xx responses by default.  Enable
  // swapping for config save errors so stale/validation/write-failure
  // messages render inside the dialog.
  document.body.addEventListener('htmx:beforeSwap', function(evt) {
    var path = evt.detail.pathInfo && evt.detail.pathInfo.requestPath;
    if (path === '/api/config/save' && evt.detail.xhr.status >= 400) {
      evt.detail.shouldSwap = true;
      evt.detail.isError = false;
    }
  });

  // Open diff dialog after diff content loads (not before — avoids
  // "Loading..." flash and onclick/htmx conflicts).
  document.body.addEventListener('htmx:afterSwap', function(evt) {
    if (evt.detail.target && evt.detail.target.id === 'diff-modal-body') {
      var dialog = document.getElementById('diff-modal');
      if (dialog && !dialog.open) dialog.showModal();
    }
  });

  // After adding a repo, redirect to its edit page.
  var addRepoForm = document.querySelector('.cfg-add-repo');
  if (addRepoForm) {
    addRepoForm.addEventListener('htmx:afterRequest', function(evt) {
      if (evt.detail.successful) {
        var input = document.getElementById('new-repo-id');
        if (input && input.value) {
          window.location = '/config/repos/' + encodeURIComponent(input.value);
        }
      }
    });
  }

  // After removing a repo, redirect to config list page.
  var removeRepoBtn = document.getElementById('remove-repo-btn');
  if (removeRepoBtn) {
    removeRepoBtn.addEventListener('htmx:afterRequest', function(evt) {
      if (evt.detail.successful) {
        window.location = '/config';
      }
    });
  }

  // Dialog close — wired up via event listener (not inline onclick)
  // to avoid potential CSP issues with inline handlers.
  var cancelBtn = document.getElementById('diff-cancel-btn');
  if (cancelBtn) {
    cancelBtn.addEventListener('click', function() {
      var dialog = document.getElementById('diff-modal');
      if (dialog) dialog.close();
    });
  }
})();
