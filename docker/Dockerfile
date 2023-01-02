FROM python:3.11-slim-bullseye

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
RUN echo "root:root"|chpasswd
# authorize SSH connection with root account
RUN sed -ri 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

RUN /etc/init.d/ssh start

RUN pip install mitmproxy

RUN useradd -mU mitmproxy

VOLUME /home/mitmproxy/.mitmproxy
VOLUME /home/mitmproxy/CONTENT
VOLUME /home/mitmproxy/addons
VOLUME /home/mitmproxy/client-certs

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +rx /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

EXPOSE 22 80 443 8080 8081 

CMD ["mitmproxy"]
