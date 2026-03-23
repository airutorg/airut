/* Config editor — schema-driven form generation */
"use strict";

(function () {
    let schema = null;
    let configData = null;
    let configGeneration = null;

    const statusEl = document.getElementById("status-text");
    const errorEl = document.getElementById("config-error");
    const successEl = document.getElementById("config-success");

    function showError(msg) {
        errorEl.textContent = msg;
        errorEl.style.display = "block";
        successEl.style.display = "none";
    }

    function showSuccess(msg) {
        successEl.textContent = msg;
        successEl.style.display = "block";
        errorEl.style.display = "none";
    }

    function hideMessages() {
        errorEl.style.display = "none";
        successEl.style.display = "none";
    }

    /* --- Fetch schema and config --- */

    async function init() {
        try {
            const [schemaRes, configRes] = await Promise.all([
                fetch("/api/config/schema"),
                fetch("/api/config"),
            ]);
            if (!schemaRes.ok || !configRes.ok) {
                showError("Failed to load config data");
                return;
            }
            schema = await schemaRes.json();
            const loaded = await configRes.json();
            configData = loaded.config;
            configGeneration = loaded.config_generation;

            statusEl.textContent =
                "Config v" +
                (configData.config_version || "?") +
                " | Generation: " +
                configGeneration;

            renderAll();
        } catch (e) {
            showError("Error loading config: " + e.message);
        }
    }

    /* --- Rendering --- */

    function renderAll() {
        renderVariables();
        renderGlobalFields();
        renderRepos();
        document.getElementById("variables-section").style.display = "";
        document.getElementById("global-section").style.display = "";
        document.getElementById("repos-section").style.display = "";
        document.getElementById("config-actions").style.display = "";
    }

    function renderVariables() {
        const container = document.getElementById("variables-editor");
        container.innerHTML = "";
        const vars = configData.vars || {};
        for (const [name, value] of Object.entries(vars)) {
            container.appendChild(createVarRow(name, value));
        }
    }

    function createVarRow(name, value) {
        const row = document.createElement("div");
        row.className = "var-row";

        const nameInput = document.createElement("input");
        nameInput.type = "text";
        nameInput.className = "var-name";
        nameInput.value = name;
        nameInput.placeholder = "Variable name";

        const isEnv =
            value && typeof value === "object" && value.__tag__ === "env";
        const modeSelect = document.createElement("select");
        modeSelect.className = "mode-select";
        modeSelect.innerHTML =
            '<option value="literal">Literal</option><option value="env">!env</option>';
        modeSelect.value = isEnv ? "env" : "literal";

        const valueInput = document.createElement("input");
        valueInput.type = "text";
        valueInput.className = "var-value";
        valueInput.value = isEnv ? value.name : (value ?? "");
        valueInput.placeholder = isEnv ? "ENV_VAR_NAME" : "Value";

        modeSelect.addEventListener("change", function () {
            valueInput.placeholder =
                modeSelect.value === "env" ? "ENV_VAR_NAME" : "Value";
        });

        const delBtn = document.createElement("button");
        delBtn.type = "button";
        delBtn.className = "btn-delete";
        delBtn.textContent = "\u00d7";
        delBtn.addEventListener("click", function () {
            row.remove();
        });

        row.appendChild(nameInput);
        row.appendChild(modeSelect);
        row.appendChild(valueInput);
        row.appendChild(delBtn);
        return row;
    }

    document
        .getElementById("add-variable-btn")
        .addEventListener("click", function () {
            document
                .getElementById("variables-editor")
                .appendChild(createVarRow("", ""));
        });

    function renderGlobalFields() {
        const container = document.getElementById("global-fields");
        container.innerHTML = "";
        const fields = schema.global || [];
        renderFieldGroup(container, fields, configData);
    }

    function renderRepos() {
        const container = document.getElementById("repos-editor");
        container.innerHTML = "";
        const repos = configData.repos || {};
        for (const [repoId, repoData] of Object.entries(repos)) {
            const block = document.createElement("div");
            block.className = "repo-block";
            block.dataset.repoId = repoId;

            const header = document.createElement("div");
            header.className = "repo-header-row";
            const h3 = document.createElement("h3");
            h3.textContent = repoId;
            header.appendChild(h3);
            block.appendChild(header);

            const repoFields = document.createElement("div");
            repoFields.className = "field-section";
            repoFields.dataset.section = "repo";
            renderFieldGroup(repoFields, schema.repo || [], repoData);
            block.appendChild(repoFields);

            // Render channel-specific fields
            if (repoData.email) {
                const emailSection = document.createElement("div");
                emailSection.className = "field-section";
                emailSection.dataset.section = "email";
                const emailHeader = document.createElement("div");
                emailHeader.className = "field-group-header";
                emailHeader.textContent = "Email Channel";
                emailSection.appendChild(emailHeader);
                renderFieldGroup(emailSection, schema.email_channel || [], repoData.email);
                block.appendChild(emailSection);
            }
            if (repoData.slack) {
                const slackSection = document.createElement("div");
                slackSection.className = "field-section";
                slackSection.dataset.section = "slack";
                const slackHeader = document.createElement("div");
                slackHeader.className = "field-group-header";
                slackHeader.textContent = "Slack Channel";
                slackSection.appendChild(slackHeader);
                renderFieldGroup(slackSection, schema.slack_channel || [], repoData.slack);
                block.appendChild(slackSection);
            }

            container.appendChild(block);
        }
    }

    function renderFieldGroup(container, fields, data) {
        let currentGroup = null;
        for (const field of fields) {
            const path = field.yaml_path || [field.name];
            const groupKey = path.length > 1 ? path[0] : null;

            if (groupKey && groupKey !== currentGroup) {
                currentGroup = groupKey;
                const gh = document.createElement("div");
                gh.className = "field-group-header";
                gh.textContent = groupKey;
                container.appendChild(gh);
            } else if (!groupKey && currentGroup) {
                currentGroup = null;
            }

            const value = getNestedValue(data, path);
            container.appendChild(createFieldRow(field, value, path));
        }
    }

    function getNestedValue(data, path) {
        let current = data;
        for (const key of path) {
            if (current == null || typeof current !== "object") return undefined;
            current = current[key];
        }
        return current;
    }

    function createFieldRow(field, value, path) {
        const row = document.createElement("div");
        row.className = "field-row";
        row.dataset.fieldName = field.name;
        row.dataset.yamlPath = JSON.stringify(path);
        row.dataset.typeName = field.type_name;

        const label = document.createElement("div");
        label.className = "field-label";
        label.innerHTML =
            escapeHtml(field.name) +
            ' <span class="scope-badge">' +
            escapeHtml(field.scope) +
            "</span>" +
            '<span class="field-doc">' +
            escapeHtml(field.doc) +
            "</span>";
        row.appendChild(label);

        const inputDiv = document.createElement("div");
        inputDiv.className = "field-input";

        const isTag =
            value && typeof value === "object" && value.__tag__;
        const mode = isTag ? value.__tag__ : "literal";

        const modeSelect = document.createElement("select");
        modeSelect.className = "mode-select";
        modeSelect.innerHTML =
            '<option value="literal">Literal</option>' +
            '<option value="var">!var</option>' +
            '<option value="env">!env</option>';
        modeSelect.value = mode;
        inputDiv.appendChild(modeSelect);

        const input = createInput(field, isTag ? "" : value);
        if (isTag) {
            input.value = value.name || "";
            input.type = "text";
        }
        inputDiv.appendChild(input);

        modeSelect.addEventListener("change", function () {
            if (modeSelect.value !== "literal") {
                input.type = "text";
                input.placeholder =
                    modeSelect.value === "env"
                        ? "ENV_VAR_NAME"
                        : "variable_name";
            } else {
                // Restore original type
                const newInput = createInput(field, null);
                input.type = newInput.type;
                input.placeholder = "";
            }
        });

        row.appendChild(inputDiv);
        return row;
    }

    function createInput(field, value) {
        const typeName = field.type_name;
        const input = document.createElement("input");

        if (typeName === "bool") {
            input.type = "checkbox";
            input.checked = !!value;
        } else if (typeName === "int" || typeName === "float") {
            input.type = "number";
            if (typeName === "float") input.step = "0.1";
            input.value = value != null ? value : "";
        } else {
            input.type = "text";
            if (Array.isArray(value)) {
                input.value = value.join(", ");
            } else if (value != null && typeof value !== "object") {
                input.value = value;
            } else {
                input.value = "";
            }
        }

        if (field.secret && typeName !== "bool") {
            input.type = "password";
            input.autocomplete = "off";
        }

        return input;
    }

    /* --- Collect form data --- */

    function collectConfig() {
        const result = JSON.parse(JSON.stringify(configData));

        // Collect variables
        result.vars = {};
        const varRows = document.querySelectorAll(
            "#variables-editor .var-row"
        );
        for (const row of varRows) {
            const name = row.querySelector(".var-name").value.trim();
            if (!name) continue;
            const mode = row.querySelector(".mode-select").value;
            const val = row.querySelector(".var-value").value;
            if (mode === "env") {
                result.vars[name] = { __tag__: "env", name: val };
            } else {
                result.vars[name] = val;
            }
        }

        // Collect global fields
        collectFields(
            document.getElementById("global-fields"),
            result
        );

        // Collect repo fields (per-section to avoid mixing channel fields)
        const repoBlocks = document.querySelectorAll(".repo-block");
        for (const block of repoBlocks) {
            const repoId = block.dataset.repoId;
            if (!result.repos) result.repos = {};
            if (!result.repos[repoId]) result.repos[repoId] = {};

            const repoSection = block.querySelector('.field-section[data-section="repo"]');
            if (repoSection) collectFields(repoSection, result.repos[repoId]);

            const emailSection = block.querySelector('.field-section[data-section="email"]');
            if (emailSection) {
                if (!result.repos[repoId].email) result.repos[repoId].email = {};
                collectFields(emailSection, result.repos[repoId].email);
            }

            const slackSection = block.querySelector('.field-section[data-section="slack"]');
            if (slackSection) {
                if (!result.repos[repoId].slack) result.repos[repoId].slack = {};
                collectFields(slackSection, result.repos[repoId].slack);
            }
        }

        return result;
    }

    function collectFields(container, target) {
        const rows = container.querySelectorAll(".field-row");
        for (const row of rows) {
            const path = JSON.parse(row.dataset.yamlPath);
            const typeName = row.dataset.typeName || "";
            const modeSelect = row.querySelector(".mode-select");
            const input = row.querySelector(
                'input[type="text"], input[type="number"], input[type="password"], input[type="checkbox"]'
            );
            if (!input || !modeSelect) continue;

            let value;
            if (modeSelect.value === "env") {
                value = { __tag__: "env", name: input.value };
            } else if (modeSelect.value === "var") {
                value = { __tag__: "var", name: input.value };
            } else if (input.type === "checkbox") {
                value = input.checked;
            } else if (input.type === "number") {
                value = input.value === "" ? null : Number(input.value);
            } else if (typeName.includes("list")) {
                // Split comma-separated values back into arrays
                value = input.value
                    ? input.value.split(",").map(function (s) { return s.trim(); })
                    : [];
            } else {
                value = input.value;
            }

            setNestedValue(target, path, value);
        }
    }

    function setNestedValue(obj, path, value) {
        for (let i = 0; i < path.length - 1; i++) {
            if (!obj[path[i]] || typeof obj[path[i]] !== "object") {
                obj[path[i]] = {};
            }
            obj = obj[path[i]];
        }
        obj[path[path.length - 1]] = value;
    }

    /* --- Review & Save --- */

    document
        .getElementById("review-btn")
        .addEventListener("click", async function () {
            hideMessages();
            const edited = collectConfig();
            try {
                const res = await fetch("/api/config/preview", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Requested-With": "XMLHttpRequest",
                    },
                    body: JSON.stringify({
                        config_generation: configGeneration,
                        config: edited,
                    }),
                });
                const data = await res.json();
                if (!data.valid) {
                    showError(data.error || "Validation failed");
                    return;
                }
                renderReview(data);
            } catch (e) {
                showError("Preview failed: " + e.message);
            }
        });

    function renderReview(data) {
        const panel = document.getElementById("review-panel");
        const content = document.getElementById("review-content");
        content.innerHTML = "";

        if (data.warnings) {
            for (const w of data.warnings) {
                const wDiv = document.createElement("div");
                wDiv.className = "review-warning";
                wDiv.textContent = w;
                content.appendChild(wDiv);
            }
        }

        const diff = data.diff || {};
        let hasChanges = false;

        const scopeLabels = {
            server: "Server-scope (restart when idle)",
            repo: "Repo-scope (listener restart)",
            task: "Task-scope (immediate)",
        };

        for (const [scope, changes] of Object.entries(diff)) {
            if (!changes || changes.length === 0) continue;
            hasChanges = true;
            const section = document.createElement("div");
            section.className = "review-scope";
            const header = document.createElement("div");
            header.className = "review-scope-header";
            header.textContent = scopeLabels[scope] || scope;
            section.appendChild(header);

            for (const change of changes) {
                const item = document.createElement("div");
                item.className = "review-change";
                const prefix = change.repo ? escapeHtml(change.repo) + " / " : "";
                item.innerHTML =
                    prefix +
                    escapeHtml(change.field) +
                    ": " +
                    '<span class="change-old">' +
                    escapeHtml(String(change.old)) +
                    "</span>" +
                    " \u2192 " +
                    '<span class="change-new">' +
                    escapeHtml(String(change.new)) +
                    "</span>" +
                    '<span class="change-doc">' +
                    escapeHtml(change.doc) +
                    "</span>";
                section.appendChild(item);
            }
            content.appendChild(section);
        }

        if (!hasChanges) {
            content.innerHTML =
                '<div class="review-no-changes">No changes detected.</div>';
        }

        panel.style.display = "";
    }

    document
        .getElementById("cancel-review-btn")
        .addEventListener("click", function () {
            document.getElementById("review-panel").style.display = "none";
        });

    document
        .getElementById("save-btn")
        .addEventListener("click", async function () {
            hideMessages();
            const edited = collectConfig();
            try {
                const res = await fetch("/api/config/save", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-Requested-With": "XMLHttpRequest",
                    },
                    body: JSON.stringify({
                        config_generation: configGeneration,
                        config: edited,
                    }),
                });
                const data = await res.json();
                if (res.status === 409) {
                    showError(
                        data.error ||
                            "Config changed externally. Please reload."
                    );
                    return;
                }
                if (!res.ok) {
                    showError(data.error || "Save failed");
                    return;
                }
                document.getElementById("review-panel").style.display = "none";
                configGeneration = data.config_generation;
                statusEl.textContent =
                    "Config v" +
                    (configData.config_version || "?") +
                    " | Generation: " +
                    configGeneration;

                let msg = "Config saved successfully.";
                if (data.reload_status === "applied") {
                    msg += " Reload applied.";
                } else if (data.reload_status === "reload_error") {
                    msg += " Warning: reload error occurred.";
                } else if (data.reload_status === "pending") {
                    msg += " Reload pending (inotify may be delayed).";
                }
                if (data.warnings) {
                    msg += " " + data.warnings.join(" ");
                }
                showSuccess(msg);
            } catch (e) {
                showError("Save failed: " + e.message);
            }
        });

    function escapeHtml(text) {
        const div = document.createElement("div");
        div.appendChild(document.createTextNode(text));
        return div.innerHTML;
    }

    init();
})();
