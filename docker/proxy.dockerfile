FROM python:3.13-slim

RUN pip install --no-cache-dir mitmproxy pyyaml

ENTRYPOINT ["mitmdump"]
