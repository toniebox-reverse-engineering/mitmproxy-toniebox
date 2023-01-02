#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset
# set -o xtrace

# Run the ip addr command
ip addr

# Start the ssh daemon
/usr/sbin/sshd -D &

iptables -t nat -A PREROUTING -i eth2 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth2 -p tcp --dport 443 -j REDIRECT --to-port 8080
ip6tables -t nat -A PREROUTING -i eth2 -p tcp --dport 80 -j REDIRECT --to-port 8080
ip6tables -t nat -A PREROUTING -i eth2 -p tcp --dport 443 -j REDIRECT --to-port 8080
    
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv4.conf.all.send_redirects=0

# Run the mitmproxy command

MITMPROXY_PATH="/home/mitmproxy/.mitmproxy"

if [[ "$1" = "mitmdump" || "$1" = "mitmproxy" || "$1" = "mitmweb" ]]; then
  mkdir -p "$MITMPROXY_PATH"
  if [ -f "$MITMPROXY_PATH/mitmproxy-ca.pem" ]; then
    usermod -o \
        -u $(stat -c "%u" "$MITMPROXY_PATH/mitmproxy-ca.pem") \
        -g $(stat -c "%g" "$MITMPROXY_PATH/mitmproxy-ca.pem") \
        mitmproxy
  fi
  gosu mitmproxy "$@"
else
  exec "$@"
fi
