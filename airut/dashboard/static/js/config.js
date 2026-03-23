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
    return;
  }

  // Add list item
  var addList = e.target.closest("[data-add-list-item]");
  if (addList) {
    var listName = addList.getAttribute("data-add-list-item");
    var container = addList.previousElementSibling;
    if (container && container.classList.contains("list-items")) {
      var idx = container.children.length;
      var row = document.createElement("div");
      row.className = "variable-row";
      row.innerHTML =
        '<input type="text" name="' +
        listName +
        ".item." +
        idx +
        '" value="" class="config-input" placeholder="Value">' +
        '<button type="button" class="config-btn-icon" data-remove-row title="Remove">&times;</button>';
      container.appendChild(row);
    }
  }
});

/* Inject CSRF header for regular form POSTs.
 *
 * HTMX handles this via the meta tag, but regular form submissions
 * need the header added manually. We intercept form submits and
 * convert to fetch with the header. After receiving the response,
 * we replace only the .config-page content (not the full document)
 * and re-initialize HTMX on the new content.
 */
document.addEventListener("submit", function (e) {
  var form = e.target;
  if (form.method !== "post" && form.method !== "POST") return;
  // Only intercept forms in the config page
  if (!form.closest(".config-page")) return;

  e.preventDefault();

  // Collect list items into hidden collectors before submitting
  _collectListItems(form);

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
        var parser = new DOMParser();
        var doc = parser.parseFromString(html, "text/html");
        var newContent = doc.querySelector(".config-page");
        var oldContent = document.querySelector(".config-page");
        if (newContent && oldContent) {
          oldContent.innerHTML = newContent.innerHTML;
          // Re-initialize HTMX on the replaced content
          if (window.htmx) {
            htmx.process(oldContent);
          }
          // Scroll to top to show save message
          window.scrollTo(0, 0);
        } else {
          window.location.reload();
        }
      });
    }
  });
});

/* Collect list item inputs into hidden textarea collectors.
 *
 * List fields use individual <input> elements for each item but
 * the server expects a newline-separated value in field.<name>.value.
 */
function _collectListItems(form) {
  var collectors = form.querySelectorAll(".list-collector");
  collectors.forEach(function (textarea) {
    var listName = textarea.getAttribute("data-list-name");
    var container = textarea.closest(".list-field");
    if (!container) return;
    var inputs = container.querySelectorAll('.list-items input[type="text"]');
    var values = [];
    inputs.forEach(function (input) {
      var v = input.value.trim();
      if (v) values.push(v);
    });
    textarea.value = values.join("\n");
  });
}
