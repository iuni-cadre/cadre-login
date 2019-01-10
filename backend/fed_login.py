import datetime

import flask
import logging
from flask import Flask, jsonify
import os, sys

from flask_pyoidc.flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata, ProviderMetadata
from flask_pyoidc.user_session import UserSession

abspath = os.path.abspath(os.path.dirname(__file__))
backend = os.path.dirname(abspath)
parent = os.path.dirname(backend)
util = parent + '/util'
sys.path.append(parent)

import util.config_reader

app = Flask(__name__)
app.config.update({'SERVER_NAME': util.config_reader.get_server_name(),
                   'SECRET_KEY': util.config_reader.get_cilogon_secret_key(),  # make sure to change this!!
                   'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=7).total_seconds(),
                   'PREFERRED_URL_SCHEME': 'http',
                   'DEBUG': True})

CLIENT = util.config_reader.get_cilogon_client_id()
CLIENT_SECRET = util.config_reader.get_cilogon_client_secret()

provider_metadata = ProviderMetadata(issuer=util.config_reader.get_cilogon_issuer(),
                                     authorization_endpoint=util.config_reader.get_cilogon_authorization_ep(),
                                     jwks_uri=util.config_reader.get_cilogon_jwks_uri())
auth_params = {'scope': ['openid', 'profile', 'email', 'org.cilogon.userinfo']}
config = ProviderConfiguration(provider_metadata=provider_metadata,
                               client_metadata=ClientMetadata(CLIENT, CLIENT_SECRET),
                               auth_request_params=auth_params)

auth = OIDCAuthentication({'default': config}, app)


@app.route('/')
@auth.oidc_auth('default')
def login():
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@app.route('/logout')
@auth.oidc_logout
def logout():
    return "You've been successfully logged out!"


@auth.error_view
def error(error=None, error_description=None):
    return jsonify({'error': error, 'message': error_description})


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    auth.init_app(app)
    app.run()

