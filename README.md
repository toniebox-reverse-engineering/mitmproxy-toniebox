# Hackiebox-Server to mitm the Boxine Cloud
You may create a vm / lxc with docker. The docker container needs to run in privileged / host mode. You should create two network interfaces. The first should be connected to your lan. The second one (named by the env-var NET_IF) should be connected to a wifi with a DHCP-Server that sets the gateway to the ip of the NET_IF interface.
Please place the client-certificates as PEM into the client-certs volume. (generated from client.der/private.der) They will be selected by their CN which is their MAC.
Place the CA as PEM into the config volume named toniebox.ca.pem. (generated from ca.der)
Convert the mitmproxy-ca-cert.pem in the certs volume into ca.der and flash it to your toniebox
There is a docker-compose file in the docker directory. Just "docker build ." your image and put the hash into "<TO-BE-FILLED>" there.
Start the app via "docker-compose -f docker-compose.yaml up"
You can access the logs via "docker logs --follow mitmproxy-toniebox"
Check the containers NET_IF IP with the port :8081 to check and inspect the communication
You may ssh into the container via ssh root@<ip> -p 8022