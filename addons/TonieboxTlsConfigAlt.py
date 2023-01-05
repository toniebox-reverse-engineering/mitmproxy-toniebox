import ipaddress
import logging
import os
import ssl
import datetime
from pathlib import Path
from typing import Any
from typing import Optional
from typing import TypedDict

from OpenSSL import crypto
from OpenSSL import SSL

from mitmproxy import certs
from mitmproxy import connection
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import tls
from mitmproxy.net import tls as net_tls
from mitmproxy.options import CONF_BASENAME
from mitmproxy.proxy import context


from mitmproxy.certs import Cert, CertStore, CertStoreEntry
from mitmproxy.addons.tlsconfig import TlsConfig

import OpenSSL
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import ExtendedKeyUsageOID
from cryptography.x509 import NameOID

from TonieboxConfig import config

CERT_EXPIRY = datetime.timedelta(days=3650)

class TonieboxTlsConfigAlt(TlsConfig):
    def __init__(self):
        logging.warn(f"Start: TonieboxTlsConfigAlt")
    
    def configure(self, updated):
        super().configure(updated)
        
        certstore_path = os.path.expanduser(ctx.options.confdir)
        self.certstore = TonieboxCertStoreAlt.from_store(
            path=certstore_path,
            basename=CONF_BASENAME,
            key_size=ctx.options.key_size,
            passphrase=ctx.options.cert_passphrase.encode("utf8")
            if ctx.options.cert_passphrase
            else None,
        )
        
    
    def get_cert(self, conn_context: context.Context) -> certs.CertStoreEntry:
        """
        This function determines the Common Name (CN), Subject Alternative Names (SANs) and Organization Name
        our certificate should have and then fetches a matching cert from the certstore.
        """
        altnames: list[str] = []
        organization: Optional[str] = None

        # Use upstream certificate if available.
        if ctx.options.upstream_cert and conn_context.server.certificate_list:
            upstream_cert = conn_context.server.certificate_list[0]
            if upstream_cert.cn:
                altnames.append(upstream_cert.cn)
            altnames.extend(upstream_cert.altnames)
            if upstream_cert.organization:
                organization = upstream_cert.organization

        # Add SNI. If not available, try the server address as well.
        if conn_context.client.sni:
            altnames.append(conn_context.client.sni)
        elif conn_context.server.address:
            altnames.append(conn_context.server.address[0])

        # As a last resort, add our local IP address. This may be necessary for HTTPS Proxies which are addressed
        # via IP. Here we neither have an upstream cert, nor can an IP be included in the server name indication.
        if not altnames:
            altnames.append(conn_context.client.sockname[0])

        # only keep first occurrence of each hostname
        altnames = list(dict.fromkeys(altnames))

        # RFC 2818: If a subjectAltName extension of type dNSName is present, that MUST be used as the identity.
        # In other words, the Common Name is irrelevant then.
        return self.certstore.get_cert_alt(conn_context, altnames[0], altnames, organization)
        #return self.certstore.get_cert(altnames[0], altnames, organization)

class TonieboxCertStoreAlt(CertStore):
  
    def get_cert_alt(
        self,
        conn_context: context.Context,
        commonname: Optional[str],
        sans: list[str],
        organization: Optional[str] = None,
    ) -> CertStoreEntry:
        """
        commonname: Common name for the generated certificate. Must be a
        valid, plain-ASCII, IDNA-encoded domain name.

        sans: A list of Subject Alternate Names.

        organization: Organization name for the generated certificate.
        """
        
        potential_keys: list[TCertId] = []
        if commonname:
            potential_keys.extend(self.asterisk_forms(commonname))
        for s in sans:
            potential_keys.extend(self.asterisk_forms(s))
        potential_keys.append("*")
        potential_keys.append((commonname, tuple(sans)))

        name = next(filter(lambda key: key in self.certs, potential_keys), None)
        if name:
            entry = self.certs[name]
        else:
            entry = CertStoreEntry(
                cert=self.dummy_cert_alt(
                    conn_context,
                    self.default_privatekey,
                    self.default_ca._cert,
                    commonname,
                    sans,
                    organization,
                ),
                privatekey=self.default_privatekey,
                chain_file=self.default_chain_file,
                #chain_certs=self.default_chain_certs, #not in v8.0.0
            )
            self.certs[(commonname, tuple(sans))] = entry
            self.expire(entry)

        return entry

    def dummy_cert_alt(
        self,
        conn_context: context.Context,
        privkey: rsa.RSAPrivateKey,
        cacert: x509.Certificate,
        commonname: Optional[str],
        sans: list[str],
        organization: Optional[str] = None,
    ) -> Cert:
        """
        Generates a dummy certificate.

        privkey: CA private key
        cacert: CA certificate
        commonname: Common name for the generated certificate.
        sans: A list of Subject Alternate Names.
        organization: Organization name for the generated certificate.

        Returns cert if operation succeeded, None if not.
        """
        upstream_cert = None
        if ctx.options.upstream_cert and conn_context.server.certificate_list:
            upstream_cert = conn_context.server.certificate_list[0]
            

        builder = x509.CertificateBuilder()
        builder = builder.issuer_name(cacert.subject)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        builder = builder.public_key(cacert.public_key())

        start = datetime.datetime(2016, 1, 1)
        if upstream_cert is None:
            builder = builder.not_valid_before(start - datetime.timedelta(days=2))
            builder = builder.not_valid_after(start + CERT_EXPIRY)
        else:
            builder = builder.not_valid_before(upstream_cert.notbefore)
            builder = builder.not_valid_after(upstream_cert.notafter)

        subject = []
        is_valid_commonname = commonname is not None and len(commonname) < 64
        if is_valid_commonname:
            assert commonname is not None
            subject.append(x509.NameAttribute(NameOID.COMMON_NAME, commonname))
        if organization is not None:
            assert organization is not None
            subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        builder = builder.subject_name(x509.Name(subject))
        builder = builder.serial_number(x509.random_serial_number())

        ss: list[x509.GeneralName] = []
        for x in sans:
            try:
                ip = ipaddress.ip_address(x)
            except ValueError:
                ss.append(x509.DNSName(x))
            else:
                ss.append(x509.IPAddress(ip))
        # RFC 5280 §4.2.1.6: subjectAltName is critical if subject is empty.
        builder = builder.add_extension(
            x509.SubjectAlternativeName(ss), critical=not is_valid_commonname
        )
        cert = builder.sign(private_key=privkey, algorithm=hashes.SHA256())  # type: ignore
        with open(f"/home/mitmproxy/config/{commonname}-cert.{config.mode}.{config.mitmproxy_version}.crt", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return Cert(cert)
    
#addons = [TonieboxTlsConfigAlt()]