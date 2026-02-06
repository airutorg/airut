FROM python:3.13-slim

RUN pip install --no-cache-dir mitmproxy pyyaml

COPY dns_responder.py /dns_responder.py
COPY proxy-entrypoint.sh /proxy-entrypoint.sh
RUN chmod +x /proxy-entrypoint.sh

ENTRYPOINT ["/proxy-entrypoint.sh"]
