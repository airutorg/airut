# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Config editor HTTP request handlers.

Schema-driven web UI for editing the server configuration file.
Forms are generated from ``schema_for_ui()`` metadata so new fields
appear automatically when added to config dataclasses.
"""

import logging
import os
import re
from collections.abc import Callable
from typing import Any

from werkzeug.wrappers import Request, Response

from airut.config.schema import schema_for_ui
from airut.config.source import (
    YAML_GLOBAL_STRUCTURE,
    YamlConfigSource,
)
from airut.dashboard.config_editor.merge import (
    group_email_fields,
    group_fields,
    lookup_email_raw,
    lookup_global_raw,
    lookup_repo_raw,
    merge_email_fields,
    merge_global_fields,
    merge_repo_fields,
)
from airut.dashboard.config_editor.parsing import (
    detect_mode,
    detect_mode_value,
    next_idx,
    parse_form_fields,
    parse_github_app_credentials,
    parse_key_value_table,
    parse_masked_secrets,
    parse_mode_value,
    parse_signing_credentials,
    parse_vars_from_form,
    remap_prefixed_fields,
)
from airut.dashboard.templating import render_template
from airut.gateway.config import (
    EmailChannelConfig,
    GlobalConfig,
    RepoServerConfig,
)
from airut.gateway.slack.config import SlackChannelConfig
from airut.sandbox.types import ResourceLimits
from airut.yaml_env import EnvVar, VarRef


logger = logging.getLogger(__name__)

_VALID_CRED_TYPES = frozenset(
    {"masked_secret", "signing_credential", "github_app"}
)


class ConfigEditor:
    """Config editor request handlers.

    Reads and writes config via ConfigSource.  Forms are rendered from
    schema metadata -- no per-field code needed for new fields.
    """

    def __init__(
        self,
        config_source: YamlConfigSource,
        status_callback: Callable[[], dict[str, object]] | None = None,
    ) -> None:
        self.source = config_source
        self._status_callback = status_callback
        self._global_schema = [
            f
            for f in schema_for_ui(GlobalConfig)
            if f.name != "resource_limits"
        ]
        self._email_schema = schema_for_ui(EmailChannelConfig)
        self._slack_schema = schema_for_ui(SlackChannelConfig)
        self._repo_schema = [
            f
            for f in schema_for_ui(RepoServerConfig)
            if f.name
            not in {
                "repo_id",
                "git_repo_url",
                "channels",
                "secrets",
                "masked_secrets",
                "signing_credentials",
                "github_app_credentials",
                "resource_limits",
                "container_env",
            }
        ]
        self._resource_limits_schema = schema_for_ui(ResourceLimits)

    def _load_raw(self) -> dict[str, Any]:
        """Load the raw config dict from the YAML source."""
        return self.source.load()

    def _save(self, raw: dict[str, Any]) -> None:
        """Save raw dict to YAML (triggers inotify reload)."""
        self.source.save(raw)

    def _require_csrf(self, request: Request) -> Response | None:
        """Check for CSRF header on mutating requests.

        Returns an error Response if the header is missing, else None.
        """
        if not request.headers.get("X-Requested-With"):
            return Response(
                render_template(
                    "config/error.html",
                    breadcrumbs=[("Config", "/config")],
                    error="Missing X-Requested-With header",
                ),
                status=403,
                content_type="text/html; charset=utf-8",
            )
        return None

    def _get_vars(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Extract the vars: section from the raw dict."""
        v = raw.get("vars")
        if isinstance(v, dict):
            return v
        return {}

    def _get_repo_ids(self, raw: dict[str, Any]) -> list[str]:
        """Return sorted list of repo IDs from the raw dict."""
        repos = raw.get("repos")
        if isinstance(repos, dict):
            return sorted(repos.keys())
        return []

    def _resolve_env(self, var_name: str) -> str | None:
        """Resolve an environment variable (for display hints)."""
        return os.environ.get(var_name)

    # ── Page handlers ────────────────────────────────────────────────

    def handle_config_index(self, request: Request) -> Response:
        """Redirect /config to /config/global."""
        return Response(
            status=302,
            headers={"Location": "/config/global"},
        )

    def handle_global(self, request: Request) -> Response:
        """Handle GET/POST for global config page."""
        if request.method == "POST":
            return self._handle_global_post(request)
        return self._handle_global_get(request)

    def _handle_global_get(
        self,
        request: Request,
        save_message: str | None = None,
        errors: dict[str, str] | None = None,
    ) -> Response:
        """Render the global settings page."""
        raw = self._load_raw()
        variables = self._get_vars(raw)
        repo_ids = self._get_repo_ids(raw)
        global_groups = group_fields(self._global_schema, YAML_GLOBAL_STRUCTURE)

        # Resource limits raw dict
        raw_resource_limits = raw.get("resource_limits")
        if not isinstance(raw_resource_limits, dict):
            raw_resource_limits = {}

        return Response(
            render_template(
                "config/global.html",
                breadcrumbs=[("Config", "/config/global")],
                global_groups=global_groups,
                global_schema=self._global_schema,
                resource_limits_schema=self._resource_limits_schema,
                raw_resource_limits=raw_resource_limits,
                variables=variables,
                repo_ids=repo_ids,
                raw=raw,
                lookup_global_raw=lookup_global_raw,
                detect_mode=detect_mode,
                detect_mode_value=detect_mode_value,
                resolve_env=self._resolve_env,
                save_message=save_message,
                errors=errors or {},
            ),
            content_type="text/html; charset=utf-8",
        )

    def _handle_global_post(self, request: Request) -> Response:
        """Process global config form submission."""
        csrf_err = self._require_csrf(request)
        if csrf_err:
            return csrf_err

        form = dict(request.form)

        # Parse global config fields
        parsed, errors = parse_form_fields(form, self._global_schema)
        if errors:
            return self._handle_global_get(request, errors=errors)

        # Parse resource limits sub-fields
        rl_parsed, rl_errors = parse_form_fields(
            remap_prefixed_fields(form, "rl_"),
            self._resource_limits_schema,
        )
        if rl_errors:
            prefixed = {f"rl_{k}": v for k, v in rl_errors.items()}
            errors.update(prefixed)
            return self._handle_global_get(request, errors=errors)

        # Parse variables
        new_vars = parse_vars_from_form(form)

        # Load current raw, merge, save
        raw = self._load_raw()
        merge_global_fields(raw, parsed, self._global_schema)

        # Merge resource limits
        if rl_parsed:
            raw["resource_limits"] = rl_parsed
        else:
            raw.pop("resource_limits", None)

        # Update vars
        if new_vars:
            raw["vars"] = new_vars
        else:
            raw.pop("vars", None)

        self._save(raw)

        return self._handle_global_get(
            request,
            save_message="Global configuration saved successfully.",
        )

    def handle_repo(self, request: Request, repo_id: str) -> Response:
        """Handle GET/POST for repo config page."""
        if request.method == "POST":
            return self._handle_repo_post(request, repo_id)
        return self._handle_repo_get(request, repo_id)

    def _handle_repo_get(
        self,
        request: Request,
        repo_id: str,
        save_message: str | None = None,
        errors: dict[str, str] | None = None,
        form_has_email: bool | None = None,
        form_has_slack: bool | None = None,
    ) -> Response:
        """Render the repo settings page."""
        raw = self._load_raw()
        repos = raw.get("repos", {})
        if repo_id not in repos:
            return Response("Repository not found", status=404)

        raw_repo = repos[repo_id]
        repo_ids = self._get_repo_ids(raw)
        variables = self._get_vars(raw)

        # Channel presence — prefer form values on error re-render
        has_email = (
            form_has_email
            if form_has_email is not None
            else "email" in raw_repo
        )
        has_slack = (
            form_has_slack
            if form_has_slack is not None
            else "slack" in raw_repo
        )
        raw_email = raw_repo.get("email", {})
        raw_slack = raw_repo.get("slack", {})

        email_groups = group_email_fields(self._email_schema)

        # Resource limits raw dict
        raw_resource_limits = raw_repo.get("resource_limits")
        if not isinstance(raw_resource_limits, dict):
            raw_resource_limits = {}

        return Response(
            render_template(
                "config/repo.html",
                breadcrumbs=[
                    ("Config", "/config/global"),
                    (repo_id, ""),
                ],
                repo_id=repo_id,
                repo_ids=repo_ids,
                raw_repo=raw_repo,
                raw_email=raw_email,
                raw_slack=raw_slack,
                has_email=has_email,
                has_slack=has_slack,
                email_groups=email_groups,
                email_schema=self._email_schema,
                slack_schema=self._slack_schema,
                repo_schema=self._repo_schema,
                resource_limits_schema=self._resource_limits_schema,
                raw_resource_limits=raw_resource_limits,
                variables=variables,
                lookup_repo_raw=lookup_repo_raw,
                lookup_email_raw=lookup_email_raw,
                detect_mode=detect_mode,
                detect_mode_value=detect_mode_value,
                resolve_env=self._resolve_env,
                save_message=save_message,
                errors=errors or {},
            ),
            content_type="text/html; charset=utf-8",
        )

    def _handle_repo_post(self, request: Request, repo_id: str) -> Response:
        """Process repo config form submission."""
        csrf_err = self._require_csrf(request)
        if csrf_err:
            return csrf_err

        form = dict(request.form)
        raw = self._load_raw()
        repos = raw.get("repos", {})
        if repo_id not in repos:
            return Response("Repository not found", status=404)

        raw_repo = repos[repo_id]

        # Parse repo-level fields
        parsed, errors = parse_form_fields(form, self._repo_schema)
        if errors:
            return self._handle_repo_get(request, repo_id, errors=errors)

        # Git repo URL
        git_parsed = parse_mode_value(form, "git_repo_url")
        if git_parsed:
            raw_repo["git"] = raw_repo.get("git", {})
            raw_repo["git"]["repo_url"] = git_parsed

        merge_repo_fields(raw_repo, parsed, self._repo_schema)

        # Resource limits
        rl_errors = self._merge_resource_limits(form, raw_repo)
        if rl_errors:
            return self._handle_repo_get(request, repo_id, errors=rl_errors)

        # Channels
        has_email = form.get("has_email") == "true"
        has_slack = form.get("has_slack") == "true"
        channel_errors = self._merge_channels(form, raw_repo)
        if channel_errors:
            return self._handle_repo_get(
                request,
                repo_id,
                errors=channel_errors,
                form_has_email=has_email,
                form_has_slack=has_slack,
            )

        # Credential pools
        self._merge_credentials(form, raw_repo)

        self._save(raw)
        return self._handle_repo_get(
            request,
            repo_id,
            save_message="Repository configuration saved successfully.",
        )

    def _merge_resource_limits(
        self,
        form: dict[str, str],
        raw_repo: dict[str, Any],
    ) -> dict[str, str] | None:
        """Parse and merge resource limits sub-fields.

        Returns errors or None.
        """
        rl_parsed, rl_errors = parse_form_fields(
            remap_prefixed_fields(form, "rl_"),
            self._resource_limits_schema,
        )
        if rl_errors:
            return {f"rl_{k}": v for k, v in rl_errors.items()}
        if rl_parsed:
            raw_repo["resource_limits"] = rl_parsed
        else:
            raw_repo.pop("resource_limits", None)
        return None

    def _merge_channels(
        self,
        form: dict[str, str],
        raw_repo: dict[str, Any],
    ) -> dict[str, str] | None:
        """Parse and merge email/slack channels. Returns errors or None."""
        has_email = form.get("has_email") == "true"
        has_slack = form.get("has_slack") == "true"

        if has_email:
            email_parsed, email_errors = parse_form_fields(
                form, self._email_schema
            )
            if email_errors:
                return email_errors
            raw_email = raw_repo.get("email", {})
            merge_email_fields(raw_email, email_parsed, self._email_schema)
            raw_repo["email"] = raw_email
        else:
            raw_repo.pop("email", None)

        if has_slack:
            slack_errors = self._merge_slack(form, raw_repo)
            if slack_errors:
                return slack_errors
        else:
            raw_repo.pop("slack", None)

        return None

    def _merge_slack(
        self,
        form: dict[str, str],
        raw_repo: dict[str, Any],
    ) -> dict[str, str] | None:
        """Parse and merge Slack channel config. Returns errors or None."""
        slack_parsed: dict[str, Any] = {}
        for sf in self._slack_schema:
            if sf.name == "authorized":
                continue  # handled separately
            mode = form.get(f"field.{sf.name}.mode", "literal")
            val = form.get(f"field.{sf.name}.value", "")
            if mode == "var" and val:
                slack_parsed[sf.name] = VarRef(val)
            elif mode == "env" and val:
                slack_parsed[sf.name] = EnvVar(val)
            elif val:
                slack_parsed[sf.name] = val

        raw_slack = raw_repo.get("slack", {})
        for k, v in slack_parsed.items():
            raw_slack[k] = v

        # Parse Slack authorized rules
        auth_text = form.get("slack_authorized", "").strip()
        if auth_text:
            auth_rules = []
            for line in auth_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if ":" not in line:
                    return {
                        "slack_authorized": (
                            f"Invalid rule (missing ':'): {line}"
                        )
                    }
                rk, rv = line.split(":", 1)
                rk = rk.strip()
                rv = rv.strip()
                if rv.lower() in ("true", "false"):
                    auth_rules.append({rk: rv.lower() == "true"})
                else:
                    auth_rules.append({rk: rv})
            raw_slack["authorized"] = auth_rules
        else:
            raw_slack.pop("authorized", None)

        raw_repo["slack"] = raw_slack
        return None

    def _merge_credentials(
        self,
        form: dict[str, str],
        raw_repo: dict[str, Any],
    ) -> None:
        """Parse and merge all credential pools."""
        secrets = parse_key_value_table(form, "secret")
        if secrets:
            raw_repo["secrets"] = secrets
        else:
            raw_repo.pop("secrets", None)

        container_env = parse_key_value_table(form, "container_env")
        if container_env:
            raw_repo["container_env"] = container_env
        else:
            raw_repo.pop("container_env", None)

        masked = parse_masked_secrets(form)
        if masked:
            raw_repo["masked_secrets"] = masked
        else:
            raw_repo.pop("masked_secrets", None)

        signing = parse_signing_credentials(form)
        if signing:
            raw_repo["signing_credentials"] = signing
        else:
            raw_repo.pop("signing_credentials", None)

        github_app = parse_github_app_credentials(form)
        if github_app:
            raw_repo["github_app_credentials"] = github_app
        else:
            raw_repo.pop("github_app_credentials", None)

    def handle_repo_new(self, request: Request) -> Response:
        """Handle GET/POST for new repo creation."""
        if request.method == "POST":
            return self._handle_repo_new_post(request)
        return self._handle_repo_new_get(request)

    def _handle_repo_new_get(
        self,
        request: Request,
        error: str | None = None,
    ) -> Response:
        """Render the new repo form."""
        raw = self._load_raw()
        repo_ids = self._get_repo_ids(raw)

        return Response(
            render_template(
                "config/repo_new.html",
                breadcrumbs=[
                    ("Config", "/config/global"),
                    ("New Repo", ""),
                ],
                repo_ids=repo_ids,
                error=error,
            ),
            content_type="text/html; charset=utf-8",
        )

    def _handle_repo_new_post(self, request: Request) -> Response:
        """Create a new repo and redirect."""
        csrf_err = self._require_csrf(request)
        if csrf_err:
            return csrf_err

        form = dict(request.form)
        repo_id = form.get("repo_id", "").strip()
        git_url = form.get("git_repo_url", "").strip()

        if not repo_id:
            return self._handle_repo_new_get(
                request, error="Repository ID is required"
            )

        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", repo_id):
            return self._handle_repo_new_get(
                request,
                error="Invalid repo ID (use letters, numbers, .-_)",
            )

        if not git_url:
            return self._handle_repo_new_get(
                request, error="Git repository URL is required"
            )

        raw = self._load_raw()
        repos = raw.setdefault("repos", {})
        if repo_id in repos:
            return self._handle_repo_new_get(
                request, error=f"Repository '{repo_id}' already exists"
            )

        # Create minimal repo entry
        new_repo: dict[str, Any] = {
            "git": {"repo_url": git_url},
            "model": "opus",
        }

        add_email = form.get("add_email") == "true"
        add_slack = form.get("add_slack") == "true"

        if add_email:
            new_repo["email"] = {
                "imap_server": "",
                "smtp_server": "",
                "username": "",
                "password": "",
                "from": "",
                "authorized_senders": [],
                "trusted_authserv_id": "",
            }

        if add_slack:
            new_repo["slack"] = {
                "bot_token": "",
                "app_token": "",
                "authorized": [{"workspace_members": True}],
            }

        # Ensure at least one channel placeholder
        if not add_email and not add_slack:
            new_repo["email"] = {
                "imap_server": "",
                "smtp_server": "",
                "username": "",
                "password": "",
                "from": "",
                "authorized_senders": [],
                "trusted_authserv_id": "",
            }

        repos[repo_id] = new_repo
        self._save(raw)

        return Response(
            status=302,
            headers={"Location": f"/config/repo/{repo_id}"},
        )

    def handle_repo_delete(self, request: Request, repo_id: str) -> Response:
        """Handle GET/POST for repo deletion."""
        if request.method == "POST":
            return self._handle_repo_delete_post(request, repo_id)
        return self._handle_repo_delete_get(request, repo_id)

    def _handle_repo_delete_get(
        self, request: Request, repo_id: str
    ) -> Response:
        """Render the deletion confirmation page."""
        raw = self._load_raw()
        repos = raw.get("repos", {})
        if repo_id not in repos:
            return Response("Repository not found", status=404)

        repo_ids = self._get_repo_ids(raw)

        return Response(
            render_template(
                "config/repo_delete.html",
                breadcrumbs=[
                    ("Config", "/config/global"),
                    (repo_id, f"/config/repo/{repo_id}"),
                    ("Delete", ""),
                ],
                repo_id=repo_id,
                repo_ids=repo_ids,
            ),
            content_type="text/html; charset=utf-8",
        )

    def _handle_repo_delete_post(
        self, request: Request, repo_id: str
    ) -> Response:
        """Delete a repo and redirect to global."""
        csrf_err = self._require_csrf(request)
        if csrf_err:
            return csrf_err

        raw = self._load_raw()
        repos = raw.get("repos", {})
        if repo_id not in repos:
            return Response("Repository not found", status=404)

        del repos[repo_id]
        self._save(raw)

        return Response(
            status=302,
            headers={"Location": "/config/global"},
        )

    # ── Fragment endpoints ───────────────────────────────────────────

    def handle_nav(self, request: Request) -> Response:
        """Return the sidebar navigation fragment."""
        raw = self._load_raw()
        repo_ids = self._get_repo_ids(raw)

        return Response(
            render_template(
                "config/components/nav.html",
                repo_ids=repo_ids,
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_field_input(self, request: Request) -> Response:
        """Return the input widget fragment for a field mode change."""
        name = request.args.get("name", "")
        type_name = request.args.get("type", "str")
        mode = request.args.get(f"field.{name}.mode", "literal")

        raw = self._load_raw()
        variables = self._get_vars(raw)

        return Response(
            render_template(
                "config/components/field_input.html",
                field_name=name,
                type_name=type_name,
                mode=mode,
                variables=variables,
                resolve_env=self._resolve_env,
                current_value="",
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_vars_add(self, request: Request) -> Response:
        """Return a new variable row fragment."""
        csrf_err = self._require_csrf(request)
        if csrf_err:
            return csrf_err

        idx = next_idx()

        return Response(
            render_template(
                "config/components/variable_row.html",
                idx=idx,
                var_name="",
                var_value="",
                var_mode="literal",
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_credential_add(self, request: Request, repo_id: str) -> Response:
        """Return a new credential card fragment."""
        csrf_err = self._require_csrf(request)
        if csrf_err:
            return csrf_err

        cred_type = request.args.get("type", "masked_secret")
        if cred_type not in _VALID_CRED_TYPES:
            return Response("Invalid credential type", status=400)

        idx = next_idx()

        raw = self._load_raw()
        variables = self._get_vars(raw)

        return Response(
            render_template(
                f"config/components/credential_{cred_type}.html",
                idx=idx,
                key="",
                entry={},
                variables=variables,
                detect_mode=detect_mode,
                detect_mode_value=detect_mode_value,
                resolve_env=self._resolve_env,
            ),
            content_type="text/html; charset=utf-8",
        )

    def handle_reload_status(self, request: Request) -> Response:
        """Return reload status polling fragment.

        Checks whether the config generation has advanced past
        ``expected_gen``.  When it has (or when no status callback is
        available), returns a fragment without the polling trigger so
        the browser stops polling.
        """
        expected_gen = request.args.get("gen", "")

        # Check if reload is complete
        if expected_gen and self._status_callback is not None:
            status = self._status_callback()
            current_gen = status.get("config_generation", 0)
            try:
                if int(str(current_gen)) >= int(expected_gen):
                    expected_gen = ""  # stop polling
            except (ValueError, TypeError):
                expected_gen = ""  # stop polling on bad values

        return Response(
            render_template(
                "config/components/reload_status.html",
                expected_gen=expected_gen,
            ),
            content_type="text/html; charset=utf-8",
        )
