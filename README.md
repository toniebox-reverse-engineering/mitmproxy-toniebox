# Hackiebox-Server to mitm the Boxine Cloud
You may create a vm / lxc with docker.

## Image preperation
Just "docker build ." your image and put the hash into "<IMAGE-ID>" of the docker-compose.yaml. Don't forget to enter your ips!

## Variants
Select the variant you want to use. You may remove the variant from the docker-compose.yaml you don't need.

### Reverse Proxy
You'll need one network (may be two in the near future, for rtnl). Please reconfigure your DNS so prod.de.tbs.toys points to the ip of your container. Please set rtnl.bxcl.de to 127.0.0.1 or something invalid. This blocks the logs of the box to be sent to the cloud. 

### Transparent Proxy
You'll need two networks. One is a normal LAN, the other (mitm) should have a DHCP that reconfigures the gateway-ip to the ip of the container itself. You may need to set the NET_IF variable to the mitm interface.
With this variant you can inspect the RTNL log messages.

## Certificates
-client-certificates as PEM into client-certs volume. (generated from client.der/private.der) They will be selected by their CN which is their MAC.

-CA as PEM into config volume named toniebox.ca.pem. (generated from ca.der)

-Convert the mitmproxy-ca-cert.pem in certs volume into ca.der and flash to your toniebox

## Startup
Start the app via "docker-compose -f docker-compose.yaml up"
You can access the logs via "docker logs --follow hackiebox-<variant-name>"
Check the containers NET_IF IP with the port :8081 to check and inspect the communication
You may ssh into the container via ssh root@<ip> -p 8022