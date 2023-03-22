#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset
# set -o xtrace

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

  # disabled. otherwise we might forward unhandled packets to the default gw
  #sysctl -w net.ipv4.ip_forward=1
  #sysctl -w net.ipv6.conf.all.forwarding=1
  #sysctl -w net.ipv4.conf.all.send_redirects=0
fi

source /opt/venv/mitmproxy/bin/activate
mitmproxy --version

if [ ! -f "$MITMPROXY_CERT_PATH/mitmproxy-ca.pem" ]; then
  echo "Creating certs..."
  faketime '2015-11-04 00:00:00' mitmweb &
  while [ ! -f "$MITMPROXY_CERT_PATH/mitmproxy-ca-cert.cer" ] \
    || [ ! -f "$MITMPROXY_CERT_PATH/mitmproxy-ca-cert.p12" ] \
    || [ ! -f "$MITMPROXY_CERT_PATH/mitmproxy-ca-cert.pem" ] \
    || [ ! -f "$MITMPROXY_CERT_PATH/mitmproxy-ca.p12" ] \
    || [ ! -f "$MITMPROXY_CERT_PATH/mitmproxy-ca.pem" ] \
    || [ ! -f "$MITMPROXY_CERT_PATH/mitmproxy-dhparam.pem" ]
  do
    sleep 1s
    echo "waiting..."
  done
  sleep 10s
  kill $!
  sleep 5s
  echo "...created!"
fi
if [ ! -f "$MITMPROXY_CERT_PATH/ca.der" ]; then
  echo "Convert mitmproxy-ca-cert.pem to ca.der for the Toniebox"
  openssl x509 -inform PEM -outform DER -in $MITMPROXY_CERT_PATH/mitmproxy-ca-cert.cer -out $MITMPROXY_CERT_PATH/ca.der
fi

if [ -v SSLKEYLOGFILE ]; then
  echo "SSLKEYLOGFILE=$SSLKEYLOGFILE"
  exec env SSLKEYLOGFILE=$SSLKEYLOGFILE mitmweb "-s /root/addons/TonieboxAddonStart.py"
fi

NGINX_CERT_FOLDER="/etc/ssl"
#https://gist.github.com/vgmoose/125271f1d9e4a1269454a64095b9e4a1
if [ ! -f "$NGINX_CERT_FOLDER/nginx-selfsigned.crt" ]; then
  echo "Creating nginx self signed certificate in $NGINX_CERT_FOLDER"
  #openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=prod.de.tbs.toys" -keyout $NGINX_CERT_FOLDER/nginx-selfsigned.key -out $NGINX_CERT_FOLDER/nginx-selfsigned.crt
  openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=prod.de.tbs.toys" -keyout mycert.key -out mycert.crt 
  #sign cert
  mkdir -p demoCA/newcerts
  touch demoCA/index.txt
  echo '01' > demoCA/serial
  openssl pkey -in $MITMPROXY_CERT_PATH/mitmproxy-ca.pem -out mitmproxy-ca.key #get CA private key
  echo "Signing Certificate with ca root"
  openssl ca -policy policy_anything -batch -days 7300 -keyfile mitmproxy-ca.key -cert $MITMPROXY_CERT_PATH/mitmproxy-ca-cert.pem -ss_cert mycert.crt -out mycert.signed.pem -extensions v3_req 
  cat $MITMPROXY_CERT_PATH/mitmproxy-ca-cert.pem mycert.signed.pem> certchain.pem #merge root ca with signed certificate
  echo "------------"
  cat certchain.pem
  echo "------------"
  mv certchain.pem mitmproxy-ca.key $NGINX_CERT_FOLDER
  #cleanup
  rm mycert.key mycert.crt
  rm -rf demoCA
fi
echo "Starting nginx"
nginx

exec mitmweb "-s /root/addons/TonieboxAddonStart.py"
