from datetime import datetime
import traceback

import flask
import requests
from flask import jsonify, render_template, request, Blueprint, redirect
import sys, os
import logging.config
import random
import string

from flask_pyoidc.user_session import UserSession

abspath = os.path.abspath(os.path.dirname(__file__))
parent = os.path.dirname(abspath)
util = parent + '/util'
sys.path.append(parent)

blueprint = Blueprint('login_api', __name__)
logger = logging.getLogger('login_api')

from .data_model import User, UserLogin, UserRole, JupyterUser

import util.config_reader
from backend import auth, db
from util.login_util import btaa_members, paying_members, paying_members_with_limited_access

cadre_dashboard_url = util.config_reader.get_cadre_dashboard_uri()


def generate_random_pwd(string_length=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(string_length))


def add_user(email, full_name, institution, login_count):
    try:
        logger.info(email)
        roles = []
        user_id = 0
        if institution in btaa_members:
            if institution in paying_members:
                roles.append('wos_gold')
            elif institution in paying_members_with_limited_access:
                roles.append('wos_limited')
            else:
                roles.append('wos')
        else:
            roles.append('guest')
        logger.info(roles)
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
            db.session.add(user_info)
            db.session.commit()
            user_id = user_info.user_id
            token = user_info.generate_auth_token(600)
            token = str(token.decode('utf-8'))
            logger.info(token)
            user_info.token = token
            db.session.commit()
        else:
            token = user_info.generate_auth_token(600)
            token = str(token.decode('utf-8'))
            logger.info(token)
            user_info.token = token
            user_info.modified_on = datetime.now()
            db.session.commit()
            user_id = user_info.user_id
        for role in roles:
            user_roles_count = UserRole.query.filter_by(user_id=user_id).count()
            if user_roles_count > 0:
                user_roles = UserRole.query.filter_by(user_id=user_id)
                for user_role in user_roles:
                    existing_role = user_role.role
                    logger.info(existing_role)
                    if existing_role not in roles:
                        # delete row
                        UserRole.query.filter_by(user_id=user_id, role=existing_role).delete()
                        db.session.commit()
            else:
                user_role = UserRole(user_id=user_id, role=role)
                db.session.add(user_role)
                db.session.commit()
        # add jupyterhub user info
        add_jupyter_user(user_id, email)
        return user_id
    except Exception as e:
        logger.error('Error occurred while adding user to the database !')
        traceback.print_tb(e.__traceback__)


def add_jupyter_user(user_id, username):
    logger.info('Creating jupyterhub user and token')
    try:
        logger.info(user_id)
        logger.info(username)
        jupyterUser = JupyterUser(user_id=user_id)
        jupyterUser.j_username = username
        pwd = generate_random_pwd(10)
        logger.info(pwd)
        jupyterUser.j_pwd = pwd

        token_args = {
            "username": username,
            "password": pwd
        }
        headers = {
            "Content-Type": "application/json"
        }
        jupyterhub_token_ep = util.config_reader.get_jupyterhub_api() + 'authorizations/token'
        response = requests.post(jupyterhub_token_ep, json=token_args, headers=headers)
        # response = requests.get(util.config_reader.get_jupyterhub_api())
        status_code = response.status_code
        logger.info(status_code)
        access_token_json = response.json()
        token = access_token_json['token']
        logger.info(token)

        jupyterUser.j_token = token
        db.session.add(jupyterUser)
        db.session.commit()
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
    user_id = add_user(email,full_name, institution, login_count)
    cadre_token = User.get_token(user_id, email)
    cadre_token = str(cadre_token.decode('utf-8'))
    jupyter_token = JupyterUser.get_token(user_id, email)
    jupyter_token = str(jupyter_token.decode('utf-8'))
    logger.info(cadre_token)
    logger.info(jupyter_token)
    return redirect(cadre_dashboard_url + email + '&cadre_token=' + cadre_token + '&jupyter_token=' + jupyter_token)


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
    user_id = add_user(email, name, 'google', login_count)
    cadre_token = User.get_token(user_id, email)
    cadre_token = str(cadre_token.decode('utf-8'))
    jupyter_token = JupyterUser.get_token(user_id, email)
    jupyter_token = str(jupyter_token.decode('utf-8'))
    logger.info(cadre_token)
    logger.info(jupyter_token)
    return redirect(cadre_dashboard_url + email + '&cadre_token=' + cadre_token + '&jupyter_token=' + jupyter_token)


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
    user_id = add_user(email, name, 'facebook', login_count)
    cadre_token = User.get_token(user_id, email)
    cadre_token = str(cadre_token.decode('utf-8'))
    jupyter_token = JupyterUser.get_token(user_id, email)
    jupyter_token = str(jupyter_token.decode('utf-8'))
    logger.info(cadre_token)
    logger.info(jupyter_token)
    return redirect(cadre_dashboard_url + email + '&cadre_token=' + cadre_token + '&jupyter_token=' + jupyter_token)


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
    return redirect(cadre_dashboard_url + email + '&token=' + token)


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


