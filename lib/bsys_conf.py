# -*- coding: utf-8 -*-
# Lib for managing configs
import yaml

def read_config(config_file):
    """
    Reads YAML config from file
    :return: cfg yaml object
    """
    try:
        with open(config_file, 'r') as ymlfile:
            global cfg
            cfg = yaml.safe_load(ymlfile)
            return cfg
    except Exception as ex:
        print("Error loading config file: {} Exit.".format(str(ex)))
        exit(-1)
