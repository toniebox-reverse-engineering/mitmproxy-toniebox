import os
import re
import logging

from pathlib import Path

import mitmproxy
from mitmproxy import ctx, http, connection, proxy, tls

from cryptography import x509
from cryptography.hazmat.backends import default_backend

class ClientCertSelect:
    def __init__(self):
        self.module_dir = Path(__file__).parent
        self.client_cert_dir = Path(self.module_dir, "client-certs")
        
    def tls_established_clientX(self, data: tls.TlsData):
        client_cert = data.ssl_conn.get_peer_certificate()
                
        if not client_cert:
            logging.error("No client cert from client?!")
            print (data.conn.get_state())
            print(len(data.conn.certificate_list))
            print(len(data.context.client.certificate_list))
            print(len(data.context.server.certificate_list))
            for cert in data.context.server.certificate_list:
                print(cert.subject)
            return
        logging.error(f"client cert from client {client_cert.get_subject()}")
        
        # Extract the CN field from the subject
        cn_match = re.search(r"CN=([^\s,]+)", client_cert.subject)
        if not cn_match:
            logging.error("No CN in client cert?!")
            return
            
        cn = cn_match.group(1)

        # List the files in the client certificate directory
        client_cert_files = os.listdir(self.client_cert_dir)

        # Check if we have a client certificate file for this client certificate
        found = False
        for client_cert_file in client_cert_files:
            # Read the client certificate file
            with open(os.path.join(self.client_cert_dir, client_cert_file), "rb") as f:
                client_cert_data = f.read()

            # Decode the client certificate file
            client_cert_cert = x509.load_pem_x509_certificate(client_cert_data, default_backend())

            # Extract the subject from the client certificate
            client_cert_subject = client_cert_cert.subject

            # Extract the CN field from the subject of the client certificate
            client_cert_cn_match = re.search(r"CN=([^\s,]+)", client_cert_subject)
            if client_cert_cn_match:
                client_cert_cn = client_cert_cn_match.group(1)

                # Check if the CN of the client certificate matches the CN of the client certificate file
                if cn == client_cert_cn:
                    # Set the client certificate file as the client certificate for the upstream server
                    ctx.options.upstream_cert = client_cert_data
                    logging.warn("Found certificate!")
                    found = True
                    break
        if not found:
            logging.error("Found no certificate...")
            data.conn.error = "No cert found..."
            #data.server.error = "No cert found..."
        
    def server_connectX(self, data: proxy.server_hooks.ServerConnectionHookData):
        client_cert = data.client.clientcert
        print(data.client)
        print(data.server)
        if not client_cert:
            logging.error("No client cert from client?!")
            return
        logging.error("client cert from client")
        
        # Extract the CN field from the subject
        cn_match = re.search(r"CN=([^\s,]+)", client_cert.subject)
        if not cn_match:
            logging.error("No CN in client cert?!")
            return
            
        cn = cn_match.group(1)

        # List the files in the client certificate directory
        client_cert_files = os.listdir(self.client_cert_dir)

        # Check if we have a client certificate file for this client certificate
        found = False
        for client_cert_file in client_cert_files:
            # Read the client certificate file
            with open(os.path.join(self.client_cert_dir, client_cert_file), "rb") as f:
                client_cert_data = f.read()

            # Decode the client certificate file
            client_cert_cert = x509.load_pem_x509_certificate(client_cert_data, default_backend())

            # Extract the subject from the client certificate
            client_cert_subject = client_cert_cert.subject

            # Extract the CN field from the subject of the client certificate
            client_cert_cn_match = re.search(r"CN=([^\s,]+)", client_cert_subject)
            if client_cert_cn_match:
                client_cert_cn = client_cert_cn_match.group(1)

                # Check if the CN of the client certificate matches the CN of the client certificate file
                if cn == client_cert_cn:
                    # Set the client certificate file as the client certificate for the upstream server
                    ctx.options.upstream_cert = client_cert_data
                    data.server.cert = client_cert_data
                    logging.warn("Found certificate!")
                    found = True
                    break
        if not found:
            logging.error("Found no certificate...")
            data.client.error = "No cert found..."
            data.server.error = "No cert found..."
                   
    def client_connectedX(self, client: connection.Client):
        client_cert = client.certificate_list[0]
        print(client.certificate_list)
        print(client_cert)
        
        if not client_cert:
            logging.error("No client cert from client?!")
            return
        logging.error("client cert from client")
        
        # Extract the CN field from the subject
        cn_match = re.search(r"CN=([^\s,]+)", client_cert.subject)
        if not cn_match:
            logging.error("No CN in client cert?!")
            return
            
        cn = cn_match.group(1)

        # List the files in the client certificate directory
        client_cert_files = os.listdir(self.client_cert_dir)

        # Check if we have a client certificate file for this client certificate
        found = False
        for client_cert_file in client_cert_files:
            # Read the client certificate file
            with open(os.path.join(self.client_cert_dir, client_cert_file), "rb") as f:
                client_cert_data = f.read()

            # Decode the client certificate file
            client_cert_cert = x509.load_pem_x509_certificate(client_cert_data, default_backend())

            # Extract the subject from the client certificate
            client_cert_subject = client_cert_cert.subject

            # Extract the CN field from the subject of the client certificate
            client_cert_cn_match = re.search(r"CN=([^\s,]+)", client_cert_subject)
            if client_cert_cn_match:
                client_cert_cn = client_cert_cn_match.group(1)

                # Check if the CN of the client certificate matches the CN of the client certificate file
                if cn == client_cert_cn:
                    # Set the client certificate file as the client certificate for the upstream server
                    ctx.options.upstream_cert = client_cert_data
                    logging.warn("Found certificate!")
                    found = True
                    break
        if not found:
            logging.error("Found no certificate...")
            client.error = "No cert found..."
            #data.server.error = "No cert found..."
                
addons = [ClientCertSelect()]