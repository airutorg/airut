FROM python:3.13-slim

COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt

COPY dns_responder.py /dns_responder.py
COPY aws_signing.py /aws_signing.py
COPY proxy_filter.py /proxy_filter.py
COPY proxy-entrypoint.sh /proxy-entrypoint.sh
RUN chmod +x /proxy-entrypoint.sh

ENTRYPOINT ["/proxy-entrypoint.sh"]
