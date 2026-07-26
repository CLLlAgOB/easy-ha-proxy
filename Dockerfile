FROM python:3.12.13-slim-trixie

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    socat ipset iptables iproute2 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# This group provides additional access to UNIX sockets on the target host.
RUN groupadd -r hadmin || true

WORKDIR /opt/haproxy-admin

COPY ./docker/app/app.py /opt/haproxy-admin/app.py
COPY ./docker/app/haproxy_admin/ /opt/haproxy-admin/haproxy_admin/
COPY ./docker/app/requirements.txt /opt/haproxy-admin/requirements.txt

RUN pip install --no-cache-dir -r /opt/haproxy-admin/requirements.txt

RUN groupadd -g 1001 haproxyadmin \
 && useradd -r -u 1001 -g 1001 haproxyadmin \
 && chown -R root:root /opt/haproxy-admin \
 && chmod -R a-w /opt/haproxy-admin \
 && mkdir -p /var/lib/haproxy-admin \
 && chown -R haproxyadmin:haproxyadmin /var/lib/haproxy-admin

USER haproxyadmin
WORKDIR /opt/haproxy-admin

CMD ["gunicorn", "--workers", "2", "--timeout", "870", "--bind", "0.0.0.0:5000", "app:app"]
