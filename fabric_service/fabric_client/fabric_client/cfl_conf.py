import os
import logging
import sys

from dist.other_pkgs.config import config as pconfig
logger = logging.getLogger(__name__)

def load_conf():
    try:
        logger.info("TCF path: %s", pconfig.TCFHOME)
        conf = pconfig.parse_configuration_files(
                ["config.toml"],
                ['config'])
        return conf
    except pconfig.ConfigurationException as e:
        logger.error(str(e))
        sys.exit(-1)