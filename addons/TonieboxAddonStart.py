import sys
import os
import logging
import importlib
from pathlib import Path

import mitmproxy
from mitmproxy import ctx

from TonieboxConfig import TonieboxConfig
from TonieboxTlsConfigAlt import TonieboxTlsConfigAlt
from TonieboxContentReplace import TonieboxContentReplace
from TonieboxClientCertSelect import TonieboxClientCertSelect

class TonieboxAddonStart:
    def __init__(self):
        logging.warn(f"Start: TonieboxAddonStart")

addons = [
    TonieboxAddonStart(),
    TonieboxConfig(),
    TonieboxTlsConfigAlt(),
    TonieboxContentReplace(),
    TonieboxClientCertSelect()
]