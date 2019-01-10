import logging
import os, errno,stat,traceback, sys, re
import configparser

abspath = os.path.abspath(os.path.dirname(__file__))
util = os.path.dirname(abspath)
parent = os.path.dirname(util)
sys.path.append(parent)

logger = logging.getLogger(__name__)


def get_cadre_config():
    try:
        config_path = parent + '/conf/cadre.config'
        if os.path.isfile(config_path):
            config = configparser.RawConfigParser()
            config.read(config_path)
            return config
        else:
            logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
            raise Exception('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        raise Exception('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')


def get_server_name():
    try:
        config = get_cadre_config()
        server_name = config['DEFAULT']['server-name']
        return server_name
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cilogon_secret_key():
    try:
        config = get_cadre_config()
        secret_key = config['CILOGON']['secret-key']
        return secret_key
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cilogon_client_id():
    try:
        config = get_cadre_config()
        client_id = config['CILOGON']['client-id']
        return client_id
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cilogon_client_secret():
    try:
        config = get_cadre_config()
        client_secret = config['CILOGON']['client-secret']
        return client_secret
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cilogon_issuer():
    try:
        config = get_cadre_config()
        issuer = config['CILOGON']['issuer']
        return issuer
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cilogon_authorization_ep():
    try:
        config = get_cadre_config()
        auth_ep = config['CILOGON']['authorization-endpoint']
        return auth_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cilogon_jwks_uri():
    try:
        config = get_cadre_config()
        jwks_uri = config['CILOGON']['jwks-uri']
        return jwks_uri
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')