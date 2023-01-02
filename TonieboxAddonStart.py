import sys
import logging
import importlib
from pathlib import Path

from TonieboxTlsConfigAlt import TonieboxTlsConfigAlt
from TonieboxContentReplace import TonieboxContentReplace
from TonieboxClientCertSelect import TonieboxClientCertSelect

class TonieboxAddonStart:
    def __init__(self):
        logging.warn(f"Start: TonieboxAddonStart")
        self.module_dir = Path(__file__).parent   

addons = [
    TonieboxAddonStart(),
    TonieboxTlsConfigAlt(),
    TonieboxContentReplace(),
    TonieboxClientCertSelect()
]