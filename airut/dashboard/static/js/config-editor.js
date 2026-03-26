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
  // Also disable the Confirm Save button if validation errors are present.
  document.body.addEventListener('htmx:afterSwap', function(evt) {
    if (evt.detail.target && evt.detail.target.id === 'diff-modal-body') {
      var dialog = document.getElementById('diff-modal');
      if (dialog && !dialog.open) dialog.showModal();

      // Disable save button when diff reports validation errors
      var hasErrors = document.getElementById('diff-has-errors');
      var saveBtn = dialog && dialog.querySelector('[hx-post$="/save"]');
      if (saveBtn) saveBtn.disabled = !!hasErrors;
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

  // Block add requests when key input is empty.  htmx does not honour
  // the HTML "required" attribute, so we validate in htmx:configRequest.
  document.body.addEventListener('htmx:configRequest', function(evt) {
    var elt = evt.detail.elt;
    if (!elt || !elt.classList.contains('cfg-list-add')) return;
    var includeId = elt.getAttribute('hx-include');
    if (!includeId) return;
    var input = document.querySelector(includeId);
    if (input && !input.value.trim()) {
      evt.preventDefault();
      input.focus();
    }
  });

  // Variable rename — prompt for new name, submit via htmx-compatible fetch.
  document.body.addEventListener('click', function(evt) {
    var btn = evt.target.closest('.cfg-var-rename-btn');
    if (!btn) return;
    var oldName = btn.getAttribute('data-var-name');
    if (!oldName) return;
    var newName = prompt('Rename variable "' + oldName + '" to:', oldName);
    if (!newName || newName === oldName) return;
    newName = newName.trim();
    if (!newName || !/^[a-zA-Z0-9_][a-zA-Z0-9_-]*$/.test(newName)) {
      alert('Invalid variable name. Use letters, digits, dashes, and underscores.');
      return;
    }
    var body = 'path=vars&key=' + encodeURIComponent(newName) +
               '&rename_from=' + encodeURIComponent(oldName);
    fetch('/api/config/add', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: body
    }).then(function(resp) {
      if (resp.ok) window.location.reload();
    });
  });

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
