# The proxy holds every task's real credentials, so its base image is named
# fully qualified (rootless podman resolves short names differently from host
# to host) and pinned by the digest of the tag's multi-arch index (a rebuild
# never picks up whatever the tag points at that day). Dependency updates
# refresh the digest (uv run python -m scripts.check_image_pins --fix). The
# server config's network.proxy_base_image replaces the image via this argument.
ARG BASE_IMAGE=docker.io/library/python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
FROM ${BASE_IMAGE}

# Install dependencies first — this layer is cached unless
# requirements.txt changes (the most stable input).
COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir --no-deps -r /requirements.txt

# Copy all application files in a single layer and set entrypoint
# executable in the same COPY (avoids a separate RUN chmod layer).
COPY dns_responder.py aws_signing.py connection_reuse.py github_app.py graphql_operations.py graphql_scope.py host_match.py node_id.py request_filter.py tool_domains.py proxy_filter.py /
COPY --chmod=755 proxy-entrypoint.sh /proxy-entrypoint.sh

ENTRYPOINT ["/proxy-entrypoint.sh"]
