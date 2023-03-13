FROM python:3.9-slim-bullseye as basebuilder  
ARG MITMPROXY_BRANCH="9.0.1"

# Install packages and configure ssh
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libpq-dev python3-dev python3-wheel \
    && apt-get install -y --no-install-recommends git \
    && apt-get install -y --no-install-recommends build-essential libssl-dev libffi-dev python3-dev cargo pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch $MITMPROXY_BRANCH https://github.com/mitmproxy/mitmproxy.git /opt/mitmproxy
#Downgrade OpenSSL so it supports SHA-1 for v1/v2 boxes
RUN sed -ri 's/"cryptography([>=]{1,2}[0-9\.,]+[<=]{1,2}[0-9\.]+)"/#Install manually/' /opt/mitmproxy/setup.py

RUN python -m venv /opt/venv/mitmproxy \
    && /opt/venv/mitmproxy/bin/pip install arpreq scapy dnspython \
    && /opt/venv/mitmproxy/bin/pip install cryptography==38.0.4 --no-binary cryptography \
    && /opt/venv/mitmproxy/bin/pip install -e "/opt/mitmproxy/.[dev]"

FROM python:3.9-slim-bullseye

EXPOSE 80 443 444 8022 8080 8081

COPY --from=basebuilder \
    /opt/mitmproxy /opt/ \
    /opt/venv /opt/

# Run the container in privileged mode
USER root

ENV NET_IF="eth1" \
    ROOT_PASS="0xbadbee" \
    TONIEBOX_CONTENT_DIR="/root/CONTENT" \
    TONIEBOX_FIXED_CERT="" \
    TONIEBOX_FALLBACK_CERT="" \
    TONIEBOX_CLIENT_CERT_DIR="/root/client-certs" \
    TONIEBOX_CONFIG_DIR="/root/config" \
    TONIEBOX_URL_PROD="prod.de.tbs.toys" \
    TONIEBOX_URL_RTNL="rtnl.bxcl.de" \
    MITMPROXY_CERT_PATH="/root/.mitmproxy"  \
    MITMPROXY_MODE="transparent" 

# Install packages and configure ssh
RUN apt-get update \
    && apt-get install -y --no-install-recommends tcpdump openssh-server \
    && apt-get install -y --no-install-recommends iptables iproute2 \
    && apt-get install -y --no-install-recommends arping \
    && apt-get install -y --no-install-recommends faketime \
    && rm -rf /var/lib/apt/lists/*

# Fix OpenSSL to support SHA-1
RUN sed -ri 's/CipherString = DEFAULT@SECLEVEL=[0-9]/CipherString = DEFAULT@SECLEVEL=1/' /etc/ssl/openssl.cnf \
#    && sed -ri 's/MinProtocol = TLSv1.2/MinProtocol = TLSv1.0/' /etc/ssl/openssl.cnf \
    && sed -i '1iopenssl_conf = default_conf' /etc/ssl/openssl.cnf

# Prepare SSH
RUN mkdir -p /run/sshd \
    && sed -ri 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -ri 's/#Port 22/Port 8022/' /etc/ssh/sshd_config

VOLUME [ \
    "/root/.mitmproxy", \
    "/root/CONTENT", \
    "/root/client-certs", \
    "/root/config", \
    "/etc/ssh" \
]

COPY docker/docker-entrypoint.sh /usr/local/bin/
RUN chmod +rx /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

CMD ["mitmweb -s /root/addons/TonieboxAddonStart.py"]
#CMD ["mitmweb", "-s /root/addons/TonieboxAddonStart.py"]

COPY addons/ /root/addons/