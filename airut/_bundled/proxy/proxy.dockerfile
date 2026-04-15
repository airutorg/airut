FROM python:3.13-slim

# Install dependencies first — this layer is cached unless
# requirements.txt changes (the most stable input).
COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir --no-deps -r /requirements.txt

# Copy all application files in a single layer and set entrypoint
# executable in the same COPY (avoids a separate RUN chmod layer).
COPY dns_responder.py aws_signing.py github_app.py graphql_scope.py node_id.py proxy_filter.py /
COPY --chmod=755 proxy-entrypoint.sh /proxy-entrypoint.sh

ENTRYPOINT ["/proxy-entrypoint.sh"]
