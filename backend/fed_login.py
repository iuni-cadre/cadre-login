import datetime

import flask
import requests
from flask import Flask, jsonify, render_template, request
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

import backend.data_model
from backend.data_model import User, UserLogin, UserTeam, UserRole, db, app

# sys.path.append("pycharm-debug-py3k.egg")

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
                   'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=7).total_seconds(),
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


def add_user(email, full_name, institution):
    user_login = UserLogin.query.filter_by(social_id=email).first()
    login_count = 0
    if not user_login:
        login_count += 1
        user_login = UserLogin(social_id=email, name=full_name, email=email, institution=institution,
                               login_count=login_count)
        db.session.add(user_login)
        db.session.commit()
    else:
        login_count = user_login.login_count
        login_count += 1
        user_login.login_count = login_count
        db.session.commit()
    return login_count


@app.route('/login')
@auth.oidc_auth('cilogon')
def cilogon_login():
    logger.info('Cilogon login')
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@app.route('/')
def home():
    return render_template('login.html')


@app.route('/login-success')
def login_success():
    return render_template('login-success.html')


@app.route('/api/auth/callback/')
def cilogon_callback():
    logger.info("API CALLBACK")
    params = request.args.get('code')

    token_args = {
        "code": params,
        "grant_type": "authorization_code",
        "redirect_uri": util.config_reader.get_cilogon_redirect_uri(),
        "client_id": util.config_reader.get_cilogon_client_id(),
        "client_secret": util.config_reader.get_cilogon_client_secret()
    }
    response = requests.post(util.config_reader.get_cilogon_token_endpoint(), data=token_args)
    access_token_json = response.json()
    access_token = access_token_json['access_token']

    user_info_args = {
        "access_token": access_token
    }

    user_info_response = requests.post(util.config_reader.get_cilogon_userinfo_endpoint(), data=user_info_args)
    user_info_response_json = user_info_response.json()

    institution = user_info_response_json['idp_name']
    email = user_info_response_json['email']
    given_name = user_info_response_json['given_name']
    family_name = user_info_response_json['family_name']
    full_name = given_name + " " + family_name

    if email is None:
        logger.error('Authentication failed.')
        return render_template('login-failed.html')
    login_count = add_user(email,full_name, institution)
    return render_template('login-success.html', full_name=full_name, institution=institution, login_count=login_count)


@app.route('/api/auth/google/login')
@auth.oidc_auth('google')
def google_login():
    logger.info('Google login')
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@app.route('/api/auth/google/callback')
def google_callback():
    logger.info("API CALLBACK")
    scope = request.args.get('scope')
    state = request.args.get('state')
    code = request.args.get('code')

    token_args = {
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": util.config_reader.get_google_redirect_uri(),
        "client_id": util.config_reader.get_google_client_id(),
        "client_secret": util.config_reader.get_google_client_secret()
    }
    response = requests.post(util.config_reader.get_google_token_endpoint(), data=token_args)
    access_token_json = response.json()
    access_token = access_token_json['access_token']
    id_token = access_token_json['id_token']
    user_info_args = {
        "access_token": access_token
    }

    user_info_response = requests.post(util.config_reader.get_google_userinfo_endpoint(), data=user_info_args)
    user_info_response_json = user_info_response.json()

    logger.info(user_info_response_json)
    email = user_info_response_json['email']
    logger.info(email)
    name = user_info_response_json['name']
    logger.info(name)
    if email is None:
        logger.error('Authentication failed.')
        return render_template('login-failed.html')
    if name is None:
        name = email
    login_count = add_user(email, name, 'google')
    return render_template('login-success.html', full_name=name, institution='google', login_count=login_count)


@app.route('/api/auth/facebook/login')
@auth.oidc_auth('facebook')
def facebook_login():
    logger.info('Facebook login')
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@app.route('/api/auth/facebook/callback')
def facebook_callback():
    logger.info("API CALLBACK")
    scope = request.args.get('scope')
    state = request.args.get('state')
    code = request.args.get('code')

    token_args = {
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": util.config_reader.get_facebook_redirect_uri(),
        "client_id": util.config_reader.get_facebook_client_id(),
        "client_secret": util.config_reader.get_facebook_client_secret()
    }
    response = requests.post(util.config_reader.get_facebook_token_endpoint(), data=token_args)
    access_token_json = response.json()
    logger.info(access_token_json)
    access_token = access_token_json['access_token']
    user_info_args = {
        "access_token": access_token,
        "fields": 'email, name'
    }

    user_info_response = requests.post(util.config_reader.get_facebook_userinfo_endpoint(), data=user_info_args)
    user_info_response_json = user_info_response.json()

    logger.info(user_info_response_json)
    email = user_info_response_json['email']
    logger.info(email)
    name = user_info_response_json['name']
    logger.info(name)
    if email is None:
        logger.error('Authentication failed.')
        return render_template('login-failed.html')
    if name is None:
        name = email
    login_count = add_user(email, name, 'google')
    return render_template('login-success.html', full_name=name, institution='facebook', login_count=login_count)


@app.route('/api/auth/microsoft/login')
@auth.oidc_auth('microsoft')
def microsoft_login():
    logger.info('Microsoft login')
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@app.route('/api/auth/microsoft/callback')
def microsoft_callback():
    logger.info("API CALLBACK")
    scope = request.args.get('scope')
    state = request.args.get('state')
    code = request.args.get('code')

    token_args = {
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": util.config_reader.get_microsoft_redirect_uri(),
        "client_id": util.config_reader.get_microsoft_client_id(),
        "client_secret": util.config_reader.get_microsoft_client_secret()
    }
    response = requests.post(util.config_reader.get_microsoft_token_endpoint(), data=token_args)
    access_token_json = response.json()
    logger.info(access_token_json)
    access_token = access_token_json['access_token']
    user_info_args = {
        "access_token": access_token
    }

    user_info_response = requests.post(util.config_reader.get_facebook_userinfo_endpoint(), data=user_info_args)
    user_info_response_json = user_info_response.json()

    logger.info(user_info_response_json)
    email = user_info_response_json['mail']
    logger.info(email)
    name = user_info_response_json['displayName']
    logger.info(name)
    if email is None:
        logger.error('Authentication failed.')
        return render_template('login-failed.html')
    if name is None:
        name = email
    login_count = add_user(email, name, 'google')
    return render_template('login-success.html', full_name=name, institution='microsoft', login_count=login_count)


@app.route('/login-fail')
def login_fail():
    return render_template('login-fail.html')


@app.route('/logout')
@auth.oidc_logout
def logout():
    return render_template('logout.html')


@app.route('/api/<path:fallback>')
def api_fallback(fallback):
    # this route should catch all api calls that aren't actually endpoints
    return jsonify({'error': 'Unknown Endpoint'}), 404


@app.route('/<path:fallback>')
def fallback(fallback):
    return render_template("login.html")


@auth.error_view
def error(error=None, error_description=None):
    return jsonify({'error': error, 'message': error_description})


if __name__ == '__main__':
    logger.info('Initializing !')
    auth.init_app(app)
    backend.data_model.create_tables()
    # login_manager = LoginManager()
    # login_manager.init_app(app)
    # login_manager.login_view = 'login'
    # pydevd.settrace('127.0.0.1', port=8881, stdoutToServer=True, stderrToServer=True)
    app.run(host='127.0.0.1', port=5000, debug=True)

