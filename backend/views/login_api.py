from datetime import datetime
import traceback

import flask
import requests
from flask import jsonify, render_template, request, Blueprint
import sys, os
import logging.config

from flask_pyoidc.user_session import UserSession

abspath = os.path.abspath(os.path.dirname(__file__))
parent = os.path.dirname(abspath)
util = parent + '/util'
sys.path.append(parent)

blueprint = Blueprint('login_api', __name__)
logger = logging.getLogger('login_api')

from .data_model import User, UserLogin

import util.config_reader
from backend import auth, db


def add_user(email, full_name, institution, login_count):
    try:
        logger.info(email)
        user_login = UserLogin.query.filter_by(social_id=email).first()
        if not user_login:
            logger.info("New user")
            login_count += 1
            user_login = UserLogin(social_id=email, name=full_name, email=email, institution=institution,
                                   login_count=login_count)
            db.session.add(user_login)
            db.session.commit()
            login_id = user_login.id
            logger.info(login_count)
        else:
            logger.info("Existing user")
            login_count = user_login.login_count
            login_count += 1
            user_login.login_count = login_count
            db.session.commit()
            login_id = user_login.id
            logger.info(login_count)
        user_info = User.query.filter_by(login_id=login_id).first()
        if not user_info:
            user_info = User(login_id=login_id, username=email, email=email)
            user_info.created_on = datetime.now()
            user_info.created_by = login_id
            token = user_info.generate_auth_token(600)
            token = str(token.decode('utf-8'))
            logger.info(token)
            user_info.token = token
            db.session.add(user_info)
            db.session.commit()
        else:
            token = user_info.generate_auth_token(600)
            token = str(token.decode('utf-8'))
            logger.info(token)
            user_info.token = token
            user_info.modified_on = datetime.now()
            db.session.commit()
        return token
    except Exception as e:
        logger.error('Error occurred while adding user to the database !')
        traceback.print_tb(e.__traceback__)


@blueprint.route('/api/auth/cilogon/login')
@auth.oidc_auth('cilogon')
def cilogon_login():
    logger.info('Cilogon login')
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@blueprint.route('/')
def home():
    return render_template('login.html')


@blueprint.route('/login-success')
def login_success():
    return render_template('login-success.html')


@blueprint.route('/api/auth/callback/')
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
    login_count = 0
    token = add_user(email,full_name, institution, login_count)
    logger.info(token)
    return render_template('login-success.html', full_name=full_name, institution=institution, token=token)


@blueprint.route('/api/auth/google/login')
@auth.oidc_auth('google')
def google_login():
    logger.info('Google login')
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@blueprint.route('/api/auth/google/callback')
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
    login_count = 0
    token = add_user(email, name, 'google', login_count)
    logger.info(token)
    return render_template('login-success.html', full_name=name, institution='google', token=token)


@blueprint.route('/api/auth/facebook/login')
@auth.oidc_auth('facebook')
def facebook_login():
    logger.info('Facebook login')
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@blueprint.route('/api/auth/facebook/callback')
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
    login_count = 0
    token = add_user(email, name, 'google', login_count)
    logger.info(token)
    return render_template('login-success.html', full_name=name, institution='facebook', token=token)


@blueprint.route('/api/auth/microsoft/login')
@auth.oidc_auth('microsoft')
def microsoft_login():
    logger.info('Microsoft login')
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@blueprint.route('/api/auth/microsoft/callback')
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
    login_count = 0
    token = add_user(email, name, 'microsoft', login_count)
    logger.info(token)
    return render_template('login-success.html', full_name=name, institution='microsoft', token=token)


@blueprint.route('/login-fail')
def login_fail():
    return render_template('login-fail.html')


@blueprint.route('/logout')
@auth.oidc_logout
def logout():
    return render_template('logout.html')


@blueprint.route('/api/<path:fallback>')
def api_fallback(fallback):
    # this route should catch all api calls that aren't actually endpoints
    return jsonify({'error': 'Unknown Endpoint'}), 404


@blueprint.route('/<path:fallback>')
def fallback(fallback):
    return render_template("login.html")


@auth.error_view
def error(error=None, error_description=None):
    return jsonify({'error': error, 'message': error_description})


