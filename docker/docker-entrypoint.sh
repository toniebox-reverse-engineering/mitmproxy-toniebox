#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset
# set -o xtrace

# Run the ip addr command
#ip addr

# Start the ssh daemon
echo "root:$ROOT_PASS"|chpasswd
#TODO: Regenerate ssh_host_keys, may already in the docker image
/usr/sbin/sshd -D &

ip addr

if [ "$MITMPROXY_MODE" = "transparent" ]; then
  iptables -t nat -A PREROUTING -i $NET_IF -p tcp --dport 80 -j REDIRECT --to-port 8080
  iptables -t nat -A PREROUTING -i $NET_IF -p tcp --dport 443 -j REDIRECT --to-port 8080
  ip6tables -t nat -A PREROUTING -i $NET_IF -p tcp --dport 80 -j REDIRECT --to-port 8080
  ip6tables -t nat -A PREROUTING -i $NET_IF -p tcp --dport 443 -j REDIRECT --to-port 8080
      
  sysctl -w net.ipv4.ip_forward=1
  sysctl -w net.ipv6.conf.all.forwarding=1
  sysctl -w net.ipv4.conf.all.send_redirects=0
fi

source /opt/venv/mitmproxy/bin/activate
mitmproxy --version

echo "$@"
# Run the mitmproxy command
if [[ "$1" = "mitmdump" || "$1" = "mitmproxy" || "$1" = "mitmweb" ]]; then
  if [ -f "$MITMPROXY_CERT_PATH/mitmproxy-ca.pem" ]; then
    usermod -o \
        -u $(stat -c "%u" "$MITMPROXY_CERT_PATH/mitmproxy-ca.pem") \
        -g $(stat -c "%g" "$MITMPROXY_CERT_PATH/mitmproxy-ca.pem") \
        mitmproxy
  fi
  gosu mitmproxy "$@"
else
  exec "$@"
fi
