/* config.js — Event delegation for config editor dynamic elements.
 *
 * Handles credential card and variable row removal via data attributes,
 * avoiding inline onclick handlers (CSP compliance).
 */
document.addEventListener("click", function (e) {
  // Remove credential card
  var removeCard = e.target.closest("[data-remove-card]");
  if (removeCard) {
    var card = removeCard.closest(".credential-card");
    if (card && confirm("Remove this credential?")) {
      card.remove();
    }
    return;
  }

  // Remove variable/key-value row
  var removeRow = e.target.closest("[data-remove-row]");
  if (removeRow) {
    var row = removeRow.closest(".variable-row");
    if (row) {
      row.remove();
    }
  }
});

/* Inject CSRF header for regular form POSTs.
 *
 * HTMX handles this via the meta tag, but regular form submissions
 * need the header added manually. We intercept form submits and
 * convert to fetch with the header.
 */
document.addEventListener("submit", function (e) {
  var form = e.target;
  if (form.method !== "post" && form.method !== "POST") return;
  // Only intercept forms in the config page
  if (!form.closest(".config-page")) return;

  e.preventDefault();

  var formData = new FormData(form);
  fetch(form.action, {
    method: "POST",
    headers: { "X-Requested-With": "XMLHttpRequest" },
    body: new URLSearchParams(formData),
  }).then(function (response) {
    if (response.redirected) {
      window.location.href = response.url;
    } else {
      return response.text().then(function (html) {
        document.documentElement.innerHTML = html;
        // Re-run scripts in the new page
        var scripts = document.querySelectorAll("script[src]");
        scripts.forEach(function (s) {
          var ns = document.createElement("script");
          ns.src = s.src;
          document.body.appendChild(ns);
        });
      });
    }
  });
});
