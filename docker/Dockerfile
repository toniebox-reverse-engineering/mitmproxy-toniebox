FROM python:3.11-slim-bullseye

ENV NET_IF="eth1"
ENV ROOT_PASS="root"
ENV TONIEBOX_CLIENT_CERT=""

ENV TONIEBOX_CONTENT_DIR="/home/mitmproxy/CONTENT"
ENV MITMPROXY_CERT_PATH="/home/mitmproxy/.mitmproxy"

# Run the container in privileged mode
USER root

# Install packages and configure ssh
RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu \
    && apt-get install -y --no-install-recommends tcpdump \
    && apt-get install -y --no-install-recommends openssh-server \
    && apt-get install -y --no-install-recommends iptables \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
    
RUN mkdir -p /run/sshd
# change password root
RUN echo "root:$ROOT_PASS"|chpasswd
# authorize SSH connection with root account
RUN sed -ri 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -ri 's/#Port 22/Port 8022/' /etc/ssh/sshd_config

RUN /etc/init.d/ssh start

RUN pip install mitmproxy
RUN useradd -mU mitmproxy
RUN mkdir -p $MITMPROXY_CERT_PATH

VOLUME /home/mitmproxy/.mitmproxy
VOLUME /home/mitmproxy/CONTENT
VOLUME /home/mitmproxy/addons
VOLUME /home/mitmproxy/client-certs

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +rx /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

EXPOSE 80 443 8022 8080 8081 

CMD ["mitmweb --web-host 0.0.0.0 --mode transparent --ssl-insecure --set client_certs=/home/mitmproxy/client-certs/$TONIEBOX_CLIENT_CERT -s /home/mitmproxy/addons/TonieboxAddonStart.py"]
#CMD ["mitmweb", "--web-host 0.0.0.0", "--mode transparent", "--ssl-insecure", "--set client_certs=/home/mitmproxy/client-certs/$TONIEBOX_CLIENT_CERT", "-s /home/mitmproxy/addons/TonieboxAddonStart.py"]