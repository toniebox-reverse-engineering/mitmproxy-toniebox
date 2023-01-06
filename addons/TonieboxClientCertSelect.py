import os
import re
import logging

from pathlib import Path

import mitmproxy
from mitmproxy import ctx, http, connection, proxy, tls

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import arpreq
from scapy.layers.l2 import getmacbyip
import binascii

from TonieboxConfig import config

class TonieboxClientCertSelect:
    def __init__(self):
        logging.warn(f"Start: TonieboxClientCertSelect")
        
    def getMacByIp(self, ip_address) -> bytes:
        #print(getmacbyip(str(ip_address)))
        return arpreq.arpreq(str(ip_address))


    #def client_connected(self, client: connection.Client):
    def server_connect(self, data: proxy.server_hooks.ServerConnectionHookData):
        if config.fixed_cert is None:
            mac = binascii.unhexlify(self.getMacByIp(data.client.address[0]).replace(':', ''))

        found = False
        # List the files in the client certificate directory
        client_cert_files = os.listdir(config.client_cert_dir)
        for client_cert_file in client_cert_files:
            # Read the client certificate file
            with open(os.path.join(config.client_cert_dir, client_cert_file), "rb") as f:
                client_cert_data = f.read()

            # Decode the client certificate file
            client_cert_cert = x509.load_pem_x509_certificate(client_cert_data, default_backend())

            # Extract the subject from the client certificate
            client_cert_cn_string = client_cert_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

            client_cert_cn = bytes.fromhex(client_cert_cn_string[2:14])

            if mac == client_cert_cn:
                # Set the client certificate file as the client certificate for the upstream server
                #ctx.options.upstream_cert = True
                ctx.options.client_certs = str(Path(config.client_cert_dir, client_cert_file))

                logging.warn("Found certificate!")
                found = True
                break
        if not found:
                if config.fallback_cert is None:
            #ctx.options.upstream_cert = False
            logging.error("Found no certificate...")
                    data.client.error = "No cert found..."
            #data.server.error = "No cert found..."
                else:
                    ctx.options.client_certs = str(Path(config.client_cert_dir, config.fallback_cert))
                    logging.warn("Using fallback client cert")
        else:
            logging.warn("Using fixed client cert")

        #print(data)
        is_rtnl_ip = False
        for ip in config.rtnl_ips:
            if ip == data.server.sni:
                is_rtnl_ip = True
                break
        if data.server.sni == "rtnl.bxcl.de" or is_rtnl_ip:
            data.server.error = "We don't like sniffers!"
            return
        print(f"client_certs={ctx.options.client_certs}")

                
#addons = [TonieboxClientCertSelect()]