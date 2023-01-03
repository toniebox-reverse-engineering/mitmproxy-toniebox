FROM python:3.9-slim-bullseye

EXPOSE 80 443 8022 8080 8081 8082

# Run the container in privileged mode
USER root

ENV NET_IF="eth1" \
    ROOT_PASS="0xbadbee" \
    TONIEBOX_CONTENT_DIR="/home/mitmproxy/CONTENT" \
    TONIEBOX_CLIENT_CERT="" \
    TONIEBOX_CLIENT_CERT_DIR="/home/mitmproxy/client-certs" \
    TONIEBOX_CONFIG_DIR="/home/mitmproxy/config" \
    TONIEBOX_CHIP="cc3200" \
    TONIEBOX_URL_PROD="prod.de.tbs.toys" \
    TONIEBOX_URL_RTNL="rtnl.bxcl.de" \
    MITMPROXY_CERT_PATH="/home/mitmproxy/.mitmproxy"  \
    MITMPROXY_MODE="transparent" 
    
ARG MITMPROXY_VERSION_LEGACY="8.0.0" \
    MITMPROXY_VERSION="9.0.1"

# Install packages and configure ssh
RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu \
    && apt-get install -y --no-install-recommends tcpdump \
    && apt-get install -y --no-install-recommends openssh-server \
    && apt-get install -y --no-install-recommends iptables \
    && apt-get install -y --no-install-recommends iproute2 \
    && apt-get install -y --no-install-recommends arping \
    && apt-get install -y --no-install-recommends gcc libpq-dev python3-dev python3-wheel \
    && rm -rf /var/lib/apt/lists/*
    
# Prepare SSH
RUN mkdir -p /run/sshd \
    && sed -ri 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -ri 's/#Port 22/Port 8022/' /etc/ssh/sshd_config

RUN python -m venv /opt/venv/mitmproxy-legacy \
    #&& /opt/venv/mitmproxy-legacy/bin/pip install --upgrade pip \
    && /opt/venv/mitmproxy-legacy/bin/pip install mitmproxy==$MITMPROXY_VERSION_LEGACY arpreq scapy
RUN python -m venv /opt/venv/mitmproxy \
    #&& /opt/venv/mitmproxy/bin/pip install --upgrade pip \
    && /opt/venv/mitmproxy/bin/pip install mitmproxy==$MITMPROXY_VERSION arpreq scapy

RUN useradd -mU mitmproxy \
    && mkdir -p $MITMPROXY_CERT_PATH

VOLUME [ \
    "/home/mitmproxy/.mitmproxy", \
    "/home/mitmproxy/CONTENT", \
    "/home/mitmproxy/client-certs", \
    "/home/mitmproxy/config", \
    "/etc/ssh" \
]

COPY docker/docker-entrypoint.sh /usr/local/bin/
RUN chmod +rx /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

CMD ["mitmweb -s /home/mitmproxy/addons/TonieboxAddonStart.py"]
#CMD ["mitmweb", "-s /home/mitmproxy/addons/TonieboxAddonStart.py"]

COPY addons/ /home/mitmproxy/addons/