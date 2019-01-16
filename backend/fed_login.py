import datetime

import flask
import logging
from flask import Flask, jsonify, render_template
import sys, os
from os import path, remove
import logging.config
import json

from flask_pyoidc.flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata, ProviderMetadata
from flask_pyoidc.user_session import UserSession

abspath = os.path.abspath(os.path.dirname(__file__))
parent = os.path.dirname(abspath)
util = parent + '/util'
sys.path.append(parent)

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


@app.route('/login')
@auth.oidc_auth('default')
def login():
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@app.route('/')
def home():
    # return 'Howdy world!'

    # using Jinja2 templates: http://flask.pocoo.org/docs/1.0/quickstart/#rendering-templates
    return render_template('login.html')

@app.route('/login-success')
def login_success():
    return render_template('login-success.html')

@app.route('/login-fail')
def login_fail():
    return render_template('login-fail.html')

@app.route('/logout')
@auth.oidc_logout
def logout():
    # return "You've been successfully logged out!"
    return render_template('logout.html')

#
# @auth.error_view
# def error(error=None, error_description=None):
#     return jsonify({'error': error, 'message': error_description})


if __name__ == '__main__':
    app.logger.info('Initializing !')
    # logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    auth.init_app(app)
    app.run()

