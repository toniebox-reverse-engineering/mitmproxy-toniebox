# Hackiebox-server to mitm the Boxine Cloud
You may create a vm / lxc with docker.

## Image preperation
Just "docker build . --tag hbs:latest" your image. Don't forget to enter your ips!

## Variants
Select the variant you want to use. You may remove the variant from the docker-compose.yaml you don't need.

### Reverse Proxy
You'll need one network. Please reconfigure your DNS so prod.de.tbs.toys points to the ip of your reverse container. Please set rtnl.bxcl.de to the ip of the nginx container.  

With this variant you can inspect the RTNL log messages.
## Config:

Mitmproxy needs to connect to boxine's server to get data from boxine's servers. To that end it needs to use the same cert that was originally on the toniebox, which can be identified by the mac address of the box. We can use an arprequest to get the mac address of an IP, but since we are using docker, which masks the connecting IP, you need to either set start the container with `--net=host` or you can map the IP of the box to its mac by hard-coding ip and mac in `addons/TonieboxConfig.py`
## Certificates
### mitmproxy-ca-cert.pem conversion
mitmproxy-ca-cert.pem in `certs`/ca/ volume is converted to ca.der automatically. Flash it to your toniebox flash:/cert/ca.der (or flash it as flash:/cert/c2.der if using the altCA patch). 
This is done via:
```
openssl x509 -inform PEM -outform DER -in mitmproxy-ca-cert.cer -out ca.der
```

### Convert **client certificate** to **PEM**-format
client-certificates as PEM into `client-certs` volume. (generated from client.der/private.der) They will be selected by their CN which is their MAC.
```
openssl x509 -inform DER -outform PEM -in client.der -out client.cer
openssl rsa -inform DER -outform PEM -in private.der -out private.key
cat client.cer private.key > client.pem
```

### Original CA as PEM
Original CA as PEM into `config` volume named toniebox.ca.pem. (generated from  the original(!) ca.der)
```
openssl x509 -inform DER -outform PEM -in ca.der -out toniebox.ca.pem
```

[Additional information about the certificates and CA.](https://github.com/toniebox-reverse-engineering/toniebox/wiki/Traffic-Sniffing/e5ce1f10e3dc63376ca03df153bd0c8e485e0ad8)

## Startup
Start the app via "docker-compose -f docker-compose.yaml up"
You can access the logs via "docker logs --follow hackiebox-<variant-name>"
Check the containers NET_IF IP with the port :8081 to check and inspect the communication
You may ssh into the container via ssh root@<ip> -p 8022

## HackieboxNG bootloader patches
You may use the altCa/altUrl patches in slot add2/add3 to allow the certificate to be loaded from flash:/cert/c2.der and set the URL to prod.revvox / rtnl.revvox.

## More Docs about mitm
See: https://github.com/toniebox-reverse-engineering/toniebox/blob/cf3528cab6610b7b008a6ebb76b8a413fe9a4e38/wiki/Traffic-Sniffing.md
