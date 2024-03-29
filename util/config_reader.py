import logging
import os, traceback, sys
import configparser

abspath = os.path.abspath(os.path.dirname(__file__))
parent = os.path.dirname(abspath)
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


def get_app_secret():
    try:
        config = get_cadre_config()
        app_secret = config['DEFAULT']['app-secret']
        return app_secret
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


def get_cilogon_token_endpoint():
    try:
        config = get_cadre_config()
        token_ep = config['CILOGON']['token-endpoint']
        return token_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')
    

def get_cilogon_userinfo_endpoint():
    try:
        config = get_cadre_config()
        userinfo_ep = config['CILOGON']['userinfo-endpoint']
        return userinfo_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cilogon_redirect_uri():
    try:
        config = get_cadre_config()
        redirect_uri = config['CILOGON']['redirect-uri']
        return redirect_uri
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cadre_db_hostname():
    try:
        config = get_cadre_config()
        db_host_name = config['DATABASE_INFO']['database-host']
        return db_host_name
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cadre_db_port():
    try:
        config = get_cadre_config()
        db_port = config['DATABASE_INFO']['database-port']
        return db_port
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cadre_db_name():
    try:
        config = get_cadre_config()
        db_name = config['DATABASE_INFO']['database-name']
        return db_name
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cadre_db_username():
    try:
        config = get_cadre_config()
        db_username = config['DATABASE_INFO']['database-username']
        return db_username
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cadre_db_pwd():
    try:
        config = get_cadre_config()
        db_pwd = config['DATABASE_INFO']['database-password']
        return db_pwd
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_google_client_id():
    try:
        config = get_cadre_config()
        client_id = config['GOOGLE']['client-id']
        return client_id
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_google_client_secret():
    try:
        config = get_cadre_config()
        client_secret = config['GOOGLE']['client-secret']
        return client_secret
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_google_auth_endpoint():
    try:
        config = get_cadre_config()
        auth_ep = config['GOOGLE']['auth-endpoint']
        return auth_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_google_token_endpoint():
    try:
        config = get_cadre_config()
        token_ep = config['GOOGLE']['token-endpoint']
        return token_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_google_issuer():
    try:
        config = get_cadre_config()
        issuer = config['GOOGLE']['issuer']
        return issuer
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_google_redirect_uri():
    try:
        config = get_cadre_config()
        redirect_uri = config['GOOGLE']['redirect-uri']
        return redirect_uri
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_google_userinfo_endpoint():
    try:
        config = get_cadre_config()
        userinfo_ep = config['GOOGLE']['userinfo-endpoint']
        return userinfo_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_facebook_client_id():
    try:
        config = get_cadre_config()
        client_id = config['FACEBOOK']['client-id']
        return client_id
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_facebook_client_secret():
    try:
        config = get_cadre_config()
        client_secret = config['FACEBOOK']['client-secret']
        return client_secret
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_facebook_auth_endpoint():
    try:
        config = get_cadre_config()
        auth_ep = config['FACEBOOK']['auth-endpoint']
        return auth_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_facebook_token_endpoint():
    try:
        config = get_cadre_config()
        token_ep = config['FACEBOOK']['token-endpoint']
        return token_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_facebook_issuer():
    try:
        config = get_cadre_config()
        issuer = config['FACEBOOK']['issuer']
        return issuer
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_facebook_redirect_uri():
    try:
        config = get_cadre_config()
        redirect_uri = config['FACEBOOK']['redirect-uri']
        return redirect_uri
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_facebook_userinfo_endpoint():
    try:
        config = get_cadre_config()
        userinfo_ep = config['FACEBOOK']['userinfo-endpoint']
        return userinfo_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_microsoft_client_id():
    try:
        config = get_cadre_config()
        client_id = config['MICROSOFT']['client-id']
        return client_id
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_microsoft_client_secret():
    try:
        config = get_cadre_config()
        client_secret = config['MICROSOFT']['client-secret']
        return client_secret
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_microsoft_auth_endpoint():
    try:
        config = get_cadre_config()
        auth_ep = config['MICROSOFT']['auth-endpoint']
        return auth_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_microsoft_issuer():
    try:
        config = get_cadre_config()
        issuer = config['MICROSOFT']['issuer']
        return issuer
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_microsoft_redirect_uri():
    try:
        config = get_cadre_config()
        redirect_uri = config['MICROSOFT']['redirect-uri']
        return redirect_uri
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_microsoft_token_endpoint():
    try:
        config = get_cadre_config()
        token_ep = config['MICROSOFT']['token-endpoint']
        return token_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_microsoft_userinfo_endpoint():
    try:
        config = get_cadre_config()
        userinfo_ep = config['MICROSOFT']['userinfo-endpoint']
        return userinfo_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cadre_dashboard_uri():
    try:
        config = get_cadre_config()
        dashboard_url = config['DEFAULT']['cadre_dashboard']
        return dashboard_url
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_jupyterhub_api():
    try:
        config = get_cadre_config()
        jupyterhub_api = config['JUPYTERHUB']['jupyterhub-apihost']
        return jupyterhub_api
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_aws_access_key():
    try:
        config = get_cadre_config()
        access_key = config['AWS']['aws-access-key-id']
        return access_key
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_aws_access_key_secret():
    try:
        config = get_cadre_config()
        access_key_secret = config['AWS']['aws-secret-access-key']
        return access_key_secret
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_aws_region():
    try:
        config = get_cadre_config()
        region_name = config['AWS']['region-name']
        return region_name
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cognito_redirect_uri():
    try:
        config = get_cadre_config()
        redirect_uri = config['AWS']['redirect-uri']
        return redirect_uri
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')

def get_cognito_logout_redirect_uri():
    try:
        config = get_cadre_config()
        logout_redirect_uri = config['AWS']['logout-redirect-uri']
        return logout_redirect_uri
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cognito_token_endpoint():
    try:
        config = get_cadre_config()
        token_ep = config['AWS']['token-endpoint']
        return token_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cognito_userinfo_endpoint():
    try:
        config = get_cadre_config()
        userinfo_ep = config['AWS']['userinfo-endpoint']
        return userinfo_ep
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cognito_client_id():
    try:
        config = get_cadre_config()
        client_id = config['AWS']['client-id']
        return client_id
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')


def get_cognito_userpool_id():
    try:
        config = get_cadre_config()
        user_pool_id = config['AWS']['user-pool-id']
        return user_pool_id
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Unable to find cadre.config file. Make sure you have cadre.config inside conf directory !')
        raise Exception('Unable to find cadre.config file !')