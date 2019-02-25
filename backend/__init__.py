from datetime import timedelta
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import sys, os
from os import path, remove
import logging.config
import json
from flask_cors import CORS

from flask_pyoidc.flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata, ProviderMetadata

abspath = os.path.abspath(os.path.dirname(__file__))
parent = os.path.dirname(abspath)
util = parent + '/util'
sys.path.append(parent)

app = Flask(__name__)
CORS(app)

# If applicable, delete the existing log file to generate a fresh log file during each execution
logfile_path = abspath + "/cadre_logging.log"
if path.isfile(logfile_path):
    remove(logfile_path)

log_conf = abspath + '/logging-conf.json'
with open(log_conf, 'r') as logging_configuration_file:
    config_dict = json.load(logging_configuration_file)

logging.config.dictConfig(config_dict)

# Log that the logger was configured
logger = logging.getLogger(__name__)
logger.info('Completed configuring logger()!')

import util.config_reader

app.config.update({'SERVER_NAME': util.config_reader.get_server_name(),
                   'SECRET_KEY': util.config_reader.get_app_secret(),
                   'PERMANENT_SESSION_LIFETIME': timedelta(days=7).total_seconds(),
                   'PREFERRED_URL_SCHEME': 'https',
                   'DEBUG': True})


CILOGON_CLIENT_ID = util.config_reader.get_cilogon_client_id()
CILOGON_CLIENT_SECRET = util.config_reader.get_cilogon_client_secret()

cilogon_auth_params = {
    'scope': ['openid', 'profile', 'email', 'org.cilogon.userinfo'],
    'redirect_uri': util.config_reader.get_cilogon_redirect_uri()
}


cilogon_provider_metadata = ProviderMetadata(issuer=util.config_reader.get_cilogon_issuer(),
                                             authorization_endpoint=util.config_reader.get_cilogon_authorization_ep(),
                                             jwks_uri=util.config_reader.get_cilogon_jwks_uri(),
                                             token_endpoint=util.config_reader.get_cilogon_token_endpoint(),
                                             userinfo_endpoint=util.config_reader.get_cilogon_userinfo_endpoint(),
                                             redirect_uris=util.config_reader.get_cilogon_redirect_uri())

cilogon_provider_config = ProviderConfiguration(provider_metadata=cilogon_provider_metadata,
                                                client_metadata=ClientMetadata(CILOGON_CLIENT_ID, CILOGON_CLIENT_SECRET),
                                                auth_request_params=cilogon_auth_params)

GOOGLE_CLIENT_ID = util.config_reader.get_google_client_id()
GOOGLE_CLIENT_SECRET = util.config_reader.get_google_client_secret()

google_auth_params = {
    'scope': ['openid', 'email', 'profile'],
    'redirect_uri': util.config_reader.get_google_redirect_uri()
}

google_provider_metadata = ProviderMetadata(issuer=util.config_reader.get_google_issuer(),
                                            authorization_endpoint=util.config_reader.get_google_auth_endpoint(),
                                            token_endpoint=util.config_reader.get_google_token_endpoint(),
                                            redirect_uris=util.config_reader.get_google_redirect_uri())

google_provider_config = ProviderConfiguration(provider_metadata=google_provider_metadata,
                                               client_metadata=ClientMetadata(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
                                               auth_request_params=google_auth_params)

FACEBOOK_CLIENT_ID = util.config_reader.get_facebook_client_id()
FACEBOOK_CLIENT_SECRET = util.config_reader.get_facebook_client_secret()

facebook_auth_params = {
    'scope': ['email'],
    'redirect_uri': util.config_reader.get_facebook_redirect_uri()
}

facebook_provider_metadata = ProviderMetadata(issuer=util.config_reader.get_facebook_issuer(),
                                            authorization_endpoint=util.config_reader.get_facebook_auth_endpoint(),
                                            token_endpoint=util.config_reader.get_facebook_auth_endpoint(),
                                            redirect_uris=util.config_reader.get_facebook_redirect_uri())

facebook_provider_config = ProviderConfiguration(provider_metadata=facebook_provider_metadata,
                                                 client_metadata=ClientMetadata(FACEBOOK_CLIENT_ID, FACEBOOK_CLIENT_SECRET),
                                                 auth_request_params=facebook_auth_params)

MICROSOFT_CLIENT_ID = util.config_reader.get_facebook_client_id()
MICROSOFT_CLIENT_SECRET = util.config_reader.get_facebook_client_secret()

microsoft_auth_params = {
    'scope': ['email', 'profile'],
    'redirect_uri': util.config_reader.get_microsoft_redirect_uri()
}

microsoft_provider_metadata = ProviderMetadata(issuer=util.config_reader.get_microsoft_issuer(),
                                            authorization_endpoint=util.config_reader.get_microsoft_auth_endpoint(),
                                            redirect_uris=util.config_reader.get_microsoft_redirect_uri())

microsoft_provider_config = ProviderConfiguration(provider_metadata=microsoft_provider_metadata,
                                               client_metadata=ClientMetadata(MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET),
                                               auth_request_params=microsoft_auth_params)


auth = OIDCAuthentication({
    'cilogon': cilogon_provider_config,
    'google': google_provider_config,
    'facebook': facebook_provider_config,
    'microsoft': microsoft_provider_config
}, app)

auth.init_app(app)

app.config['SECRET_KEY'] = util.config_reader.get_app_secret()
url = util.config_reader.get_cadre_db_hostname() + ':' + util.config_reader.get_cadre_db_port()
DB_URL = 'postgres://{user}:{pw}@{url}/{db}'.format(user=util.config_reader.get_cadre_db_username(),
                                                    pw=util.config_reader.get_cadre_db_pwd(),
                                                    url=url,
                                                    db=util.config_reader.get_cadre_db_name())
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

from .views import login_api, user_api, data_model
app.register_blueprint(data_model.blueprint)
app.register_blueprint(login_api.blueprint)
app.register_blueprint(user_api.blueprint)



