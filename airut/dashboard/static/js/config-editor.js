/**
 * Config editor client-side interactions.
 *
 * - Source selector toggle (Not set / Literal / !env / !var)
 * - Unsaved changes guard (beforeunload)
 * - Expand/collapse for keyed collections
 * - Channel enable/disable toggles
 */

// ── Channel section toggle ──────────────────────────────────────

function toggleChannelSection(checkbox) {
    "use strict";
    var channelId = checkbox.dataset.channel;
    var fieldset = document.getElementById(channelId + "-fields");
    var label = checkbox.parentElement.querySelector(".cfg-toggle-label");
    if (fieldset) {
        if (checkbox.checked) {
            fieldset.disabled = false;
            fieldset.classList.remove("cfg-channel-disabled");
        } else {
            fieldset.disabled = true;
            fieldset.classList.add("cfg-channel-disabled");
        }
    }
    if (label) {
        label.textContent = checkbox.checked ? "Enabled" : "Not enabled";
    }
}

(function () {
    "use strict";

    // Track whether the form has been modified
    var formDirty = false;

    // ── Source selector ─────────────────────────────────────────────

    document.addEventListener("click", function (e) {
        var btn = e.target.closest(".cfg-source-btn");
        if (!btn) return;

        var sourceGroup = btn.closest(".cfg-source");
        if (!sourceGroup) return;

        var source = btn.dataset.source;
        var path = sourceGroup.dataset.path;

        // Update active state
        sourceGroup.querySelectorAll(".cfg-source-btn").forEach(function (b) {
            b.classList.remove("active");
        });
        btn.classList.add("active");

        // Find the hidden _source input and the value input
        var form = document.getElementById("config-form");
        if (!form) return;

        var sourceInput = form.querySelector(
            'input[name="' + path + '._source"]'
        );
        var valueInput = form.querySelector(
            '[name="' + path + '._value"]'
        );

        if (sourceInput) {
            sourceInput.value = source;
        }

        if (valueInput) {
            if (source === "unset") {
                valueInput.disabled = true;
                valueInput.value = "";
            } else {
                valueInput.disabled = false;
            }
        }

        // Update field visual state
        var field = btn.closest(".cfg-field");
        if (field) {
            if (source === "unset") {
                field.classList.remove("set");
                field.classList.add("unset");
            } else {
                field.classList.remove("unset");
                field.classList.add("set");
            }
        }

        formDirty = true;
    });

    // ── Unsaved changes guard ────────────────────────────────────

    document.addEventListener("input", function () {
        formDirty = true;
    });

    document.addEventListener("change", function () {
        formDirty = true;
    });

    window.addEventListener("beforeunload", function (e) {
        if (formDirty) {
            e.preventDefault();
            e.returnValue = "";
        }
    });

    // Clear dirty flag after successful save
    document.addEventListener("htmx:afterRequest", function (e) {
        if (
            e.detail.target &&
            e.detail.target.id === "save-result" &&
            e.detail.successful
        ) {
            formDirty = false;
        }
    });

    // ── Expand/collapse ──────────────────────────────────────────

    // Handled via onclick in the template HTML (classList.toggle)

    // ── Dashboard disable warning ─────────────────────────────

    var form = document.getElementById("config-form");
    if (form) {
        form.addEventListener("submit", function (e) {
            // Check if dashboard_enabled is being set to false
            var enabledSource = form.querySelector(
                'input[name$="dashboard.enabled._source"]'
            );
            var enabledValue = form.querySelector(
                '[name$="dashboard.enabled._value"]'
            );

            if (enabledSource && enabledValue) {
                var isDisabling =
                    enabledSource.value === "literal" &&
                    (enabledValue.value === "false" ||
                        enabledValue.value === "no" ||
                        enabledValue.value === "off");

                if (isDisabling) {
                    var confirmed = confirm(
                        "Warning: Disabling the dashboard will make this " +
                            "editor inaccessible. You will need to edit the " +
                            "config file directly to re-enable it.\n\n" +
                            "Continue?"
                    );
                    if (!confirmed) {
                        e.preventDefault();
                        e.stopPropagation();
                        return false;
                    }
                }
            }
        });
    }
})();
