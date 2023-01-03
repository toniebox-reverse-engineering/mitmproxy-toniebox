import sys
import os
import logging
from pathlib import Path

import mitmproxy
from mitmproxy import ctx, version

class TonieboxConfig:
    def __init__(self):
        logging.warn(f"Start: TonieboxConfig")
        self.module_dir = Path(__file__).parent
        sys.path.append(self.module_dir)
        logging.warn(f"module_path={self.module_dir}")

        env_conf_dir = os.environ.get("TONIEBOX_CONFIG_DIR")
        env_mode = os.environ.get("MITMPROXY_MODE")
        env_url_prod = os.environ.get("TONIEBOX_URL_PROD")
        env_url_rtnl = os.environ.get("TONIEBOX_URL_RTNL")
        #
        env_cont_dir = os.environ.get("TONIEBOX_CONTENT_DIR")
        #
        env_cert_dir = os.environ.get("TONIEBOX_CLIENT_CERT_DIR")
        env_fixed_cert = os.environ.get("TONIEBOX_CLIENT_CERT")


        if env_conf_dir is None:
            self.config_dir = Path(self.module_dir, "config")
        else:
            self.config_dir = Path(env_conf_dir)

        self.mitmproxy_version = version.get_dev_version()

        self.url_real_prod = "prod.de.tbs.toys"
        self.url_real_rtnl = "rtnl.bxcl.de"
        self.url_fake_prod = env_url_prod
        self.url_fake_rtnl = env_url_rtnl

        if env_mode == "reverse":
            ctx.options.listen_port = 443
            if self.mitmproxy_version == "8.0.0":
                #ctx.options.listen_host = "192.168.123.175"
                ctx.options.mode = f"reverse:https://{self.url_real_prod}:443"#, reverse:tls://{self.url_real_rtnl}:443@8090"
            else:
                ctx.options.mode = [f"reverse:https://{self.url_real_prod}:443"]#, f"reverse:tls://{self.url_real_rtnl}:443@10.12.0.176:443"]

            self.mode = env_mode
            #ctx.options.allow_hosts = [f"{self.url_fake_prod}"]
            #ctx.options.tcp_hosts = [f"{self.url_fake_rtnl}"]
        else:
            if self.mitmproxy_version == "8.0.0":
                ctx.options.mode = "transparent"
            else:
                ctx.options.mode = ["transparent"]
            self.mode = "transparent"
            #ctx.options.allow_hosts = [f"{self.url_real_prod}"]
            #ctx.options.tcp_hosts = [f"{self.url_real_rtnl}"]

        ctx.options.ssl_insecure=True #Workaround, as the ssl_verify_upstream_trusted_ca option doesn't work...
        ctx.options.ssl_verify_upstream_trusted_ca = str(Path(self.config_dir, "toniebox.ca.pem"))
        ctx.options.web_host = "0.0.0.0"
        logging.warn(
            f"mode={ctx.options.mode}, " +
            f"ssl_verify_upstream_trusted_ca={ctx.options.ssl_verify_upstream_trusted_ca}, " +
            f"ssl_insecure={ctx.options.ssl_insecure}"
        )
        logging.warn(
            f"allow_hosts={ctx.options.allow_hosts}, " +
            f"tcp_hosts={ctx.options.tcp_hosts}"
        )


        if env_cont_dir is None:
            self.content_dir = Path(self.module_dir, "CONTENT")
        else:
            self.content_dir = Path(env_cont_dir)
        logging.warn(f"content_dir={self.content_dir}")

        
        if env_cert_dir is None:
            self.client_cert_dir = Path(self.module_dir, "client-certs")
        else:
            self.client_cert_dir = Path(env_cert_dir)

        if env_fixed_cert is None or env_fixed_cert == "":
            self.fixed_cert = None
        else:
            self.fixed_cert = env_fixed_cert
            ctx.options.client_certs = str(Path(self.client_cert_dir, self.fixed_cert))

        logging.warn(f"client_cert_dir={self.client_cert_dir}, fixed_cert={self.fixed_cert}")

config = TonieboxConfig()
#addons = [config]
