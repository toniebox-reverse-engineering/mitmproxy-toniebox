import sys
import os
import logging
import importlib
from pathlib import Path

import mitmproxy
from mitmproxy import ctx

from TonieboxTlsConfigAlt import TonieboxTlsConfigAlt
from TonieboxContentReplace import TonieboxContentReplace
from TonieboxClientCertSelect import TonieboxClientCertSelect

class TonieboxAddonStart:
    def __init__(self):
        logging.warn(f"Start: TonieboxAddonStart")
        self.module_dir = Path(__file__).parent

        env_conf_dir = os.environ.get("TONIEBOX_CONFIG_DIR")
        if env_conf_dir is None:
            self.config_dir = Path(self.module_dir, "config")
        else:
            self.config_dir = Path(env_conf_dir)

        ctx.options.ssl_insecure=True #Workaround, as the ca certificate options doesn't work...
        ctx.options.ssl_verify_upstream_trusted_ca = str(Path(self.config_dir, "toniebox.ca.pem"))
        logging.warn(f"ssl_verify_upstream_trusted_ca={ctx.options.ssl_verify_upstream_trusted_ca}, ssl_insecure={ctx.options.ssl_insecure}")

addons = [
    TonieboxAddonStart(),
    TonieboxTlsConfigAlt(),
    TonieboxContentReplace(),
    TonieboxClientCertSelect()
]