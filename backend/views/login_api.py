import json
from datetime import datetime
import traceback

import flask
import requests
from flask import jsonify, render_template, request, Blueprint, redirect, escape, abort, Response
import sys, os
import logging
import logging.config
import random
import string
import boto3
import base64

from flask_pyoidc.user_session import UserSession

abspath = os.path.abspath(os.path.dirname(__file__))
parent = os.path.dirname(abspath)
util = parent + '/util'
sys.path.append(parent)

blueprint = Blueprint('login_api', __name__)
logger = logging.getLogger('login_api')
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('nose').setLevel(logging.CRITICAL)
logging.getLogger('s3transfer').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)

from .data_model import User, UserLogin, UserRole, JupyterUser, UserToken

import util.config_reader
from backend import auth, db
from util.login_util import btaa_members, paying_members, trial_members

cadre_dashboard_url = util.config_reader.get_cadre_dashboard_uri()


def generate_random_pwd(string_length=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(string_length))


def add_user(username, email, full_name, institution,  aws_username):
    try:
        roles = []
        user_id = 0
        
        if institution in paying_members:
            roles.append('wos_gold')
        elif institution in btaa_members:
            roles.append('wos')
        elif institution in trial_members:
            roles.append('wos_trial')
        else:
            roles.append('guest')
        user_login = UserLogin.query.filter_by(social_id=username).first()
        if not user_login:
            logger.info("Trying to add New user")
            user_login = UserLogin(social_id=username,
                                   name=full_name,
                                   email=email,
                                   institution=institution)
            db.session.add(user_login)
            db.session.commit()
            login_id = user_login.id
        else:
            logger.info("Updating existing user")
            db.session.commit()
            login_id = user_login.id
        user_info = User.query.filter_by(login_id=login_id).first()
        if not user_info:
            user_info = User(login_id=login_id, username=username, email=email)
            user_info.created_on = datetime.now()
            user_info.created_by = login_id
            user_info.aws_username = aws_username
            db.session.add(user_info)
            db.session.commit()
            user_id = user_info.user_id
        else:
            user_info.aws_username = aws_username
            user_info.modified_on = datetime.now()
            db.session.commit()
            user_id = user_info.user_id
        for role in roles:
            user_roles_count = UserRole.query.filter_by(user_id=user_id).count()
            if user_roles_count > 0:
                user_roles = UserRole.query.filter_by(user_id=user_id)
                for user_role in user_roles:
                    existing_role = user_role.role
                    if existing_role not in roles:
                        # delete row
                        UserRole.query.filter_by(user_id=user_id, role=existing_role).delete()
                        db.session.commit()
            else:
                user_role = UserRole(user_id=user_id, role=role)
                db.session.add(user_role)
                db.session.commit()
        # add jupyterhub user info
        add_jupyter_user(user_id, username)
        add_user_to_usergroup(aws_username, roles[0])
        if institution in trial_members:
            add_user_to_usergroup(aws_username, 'wos_trial')
        # add_user_to_userpool(username)
        return user_id
    except Exception as e:
        logger.error('Error occurred while adding user to the database. Error is : ' + str(e))
        traceback.print_tb(e.__traceback__)


def add_tokens(user_id, access_token, id_token, refresh_token):
    try:
        token_count = UserToken.query.filter_by(user_id=user_id).count()
        if token_count > 0:
            existing_tokens = UserToken.query.filter_by(user_id=user_id)
            for existing_token in existing_tokens:
                if existing_token.type == 'access':
                    existing_token.token = access_token
                    existing_token.token_expiration_for_access_id_token()
                elif existing_token.type == 'id':
                    existing_token.token = id_token
                    existing_token.token_expiration_for_access_id_token()
                elif existing_token.type == 'refresh':
                    existing_token.token = refresh_token
                    existing_token.token_expiration_for_refresh_token()
                db.session.commit()
        else:
            access_token_do = UserToken(user_id=user_id, type='access', token=access_token)
            access_token_do.token_expiration_for_access_id_token()
            db.session.add(access_token_do)
            db.session.commit()

            id_token_do = UserToken(user_id=user_id, type='id', token=id_token)
            id_token_do.token_expiration_for_access_id_token()
            db.session.add(id_token_do)
            db.session.commit()

            refresh_token_do = UserToken(user_id=user_id, type='refresh', token=refresh_token)
            refresh_token_do.token_expiration_for_refresh_token()
            db.session.add(refresh_token_do)
            db.session.commit()
    except Exception as e:
        logger.error('Error occurred while adding user to the database. Error is : ' + str(e))
        traceback.print_tb(e.__traceback__)


def add_jupyter_user(user_id, username):
    logger.info('Creating jupyterhub user and token')
    try:
        jupyterUser = JupyterUser.query.filter_by(user_id=user_id).first()
        pwd = generate_random_pwd(10)
        if not jupyterUser:
            jupyterUser = JupyterUser(user_id=user_id)
            jupyterUser.jupyter_username = username
            logger.info(pwd)
            jupyterUser.jupyter_pwd = pwd
            token = generate_j_token(pwd, username)
            jupyterUser.jupyter_token = token
            db.session.add(jupyterUser)
            db.session.commit()
        else:
            pwd = jupyterUser.jupyter_pwd
            token = generate_j_token(pwd, username)
            logger.info(token)
            jupyterUser.jupyter_token = token
            db.session.commit()
    except Exception as e:
        logger.error('Error occurred while adding user to the database !. Error is ' + str(e))
        traceback.print_tb(e.__traceback__)


def add_user_to_usergroup(username, role):
    logger.info('Adding user to cognito user group')
    try:
        cognito_client = boto3.client('cognito-idp',
                                  aws_access_key_id=util.config_reader.get_aws_access_key(),
                                  aws_secret_access_key=util.config_reader.get_aws_access_key_secret(),
                                  region_name=util.config_reader.get_aws_region())
        if 'wos_trial' in role:
            response = cognito_client.admin_add_user_to_group(
                UserPoolId=util.config_reader.get_cognito_userpool_id(),
                Username=username,
                GroupName='wos_trial'
            )
            response = cognito_client.admin_add_user_to_group(
                UserPoolId=util.config_reader.get_cognito_userpool_id(),
                Username=username,
                GroupName='MAG'
            )
        elif  'wos' in role:
            response = cognito_client.admin_add_user_to_group(
                UserPoolId=util.config_reader.get_cognito_userpool_id(),
                Username=username,
                GroupName='WOS'
            )
            response = cognito_client.admin_add_user_to_group(
                UserPoolId=util.config_reader.get_cognito_userpool_id(),
                Username=username,
                GroupName='MAG'
            )
        else:
            response = cognito_client.admin_add_user_to_group(
                UserPoolId='cadre',
                Username=username,
                GroupName='MAG'
            )
    except Exception as e:
        logger.error('Error occurred while adding user to cognito user group !. Error is ' + str(e))
        traceback.print_tb(e.__traceback__)

def list_user_cognito_groups(username):
    logger.info('Listing user Cognito Groups')
    try:
        base_group = ["MAG"]
        logger.info(username)
        cognito_client = boto3.client('cognito-idp',
                                  aws_access_key_id=util.config_reader.get_aws_access_key(),
                                  aws_secret_access_key=util.config_reader.get_aws_access_key_secret(),
                                  region_name=util.config_reader.get_aws_region())
        response = cognito_client.admin_list_groups_for_user(
            Username=username,
            UserPoolId=util.config_reader.get_cognito_userpool_id()
        )
        cognito_groups = [g.get("GroupName") for g in response.get("Groups")]
        if cognito_groups:
            return cognito_groups
        return base_group
    except Exception as e:
        logger.error('Error occurred while listing user Cognito Groups. Error is ' + str(e))
        traceback.print_tb(e.__traceback__)
    

def generate_j_token(pwd, username):
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
    access_token_json = response.json()
    token = access_token_json['token']
    return token


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


@blueprint.route('/api/cognito/callback')
def cognito_callback():
    code = request.args.get('code')

    token_args = {
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": util.config_reader.get_cognito_redirect_uri(),
        "client_id": util.config_reader.get_cognito_client_id()
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    response = requests.post(util.config_reader.get_cognito_token_endpoint(),
                             data=token_args,
                             headers=headers)
    logger.info(response)
    status_code = response.status_code
    logger.info(status_code)
    if status_code == 200:
        access_token_json = response.json()
        access_token = access_token_json['access_token']
        id_token = access_token_json['id_token']
        refresh_token = access_token_json['refresh_token']
        expires_in = access_token_json['expires_in']
        user_info_header = {
            'Authorization': 'Bearer ' + access_token
        }

        user_info_response = requests.get(util.config_reader.get_cognito_userinfo_endpoint(), headers=user_info_header)
        user_info_response_code = user_info_response.status_code
        if user_info_response_code == 200:
            user_info_response_json = user_info_response.json()
            logger.info(user_info_response_json)
            aws_username = user_info_response_json['username']
            # aws_username = aws_username.upper()
            if 'CILOGON' in aws_username.upper():
                institution = user_info_response_json['custom:idp_name']
            elif 'GOOGLE' in aws_username.upper():
                institution = 'google'
            elif 'Microsoft' in aws_username:
                institution = 'microsoft'
            else:
                institution = 'guest'
            email = user_info_response_json['email']
            full_name = ""
            if 'given_name' in user_info_response_json:
                given_name = user_info_response_json['given_name']
                full_name = given_name
            if 'family_name' in user_info_response_json:
                family_name = user_info_response_json['family_name']
                full_name += " " + family_name

            if email is None:
                logger.error('Authentication failed.')
                return render_template('login-failed.html')

            names = email.split('@')
            username = names[0]

            # base32 encoded username
            username = base64.b32encode(bytes(username, 'utf-8'))
            username = username.decode('ascii')
            if '=' in username:
                username = username.replace('=', '')

            username = username.lower()

            user_id = add_user(username, email, full_name, institution, aws_username)
            add_tokens(user_id, access_token, id_token, refresh_token)
            add_jupyter_user(user_id, username)
            cadre_token = UserToken.get_access_token(user_id).token
            jupyter_token = JupyterUser.get_token(user_id, username)
            logger.info('User with username ' + username + ' added..')

            return redirect(cadre_dashboard_url + username + '&cadre_token=' + cadre_token + '&jupyter_token=' + jupyter_token)
        else:
            logger.error('Authentication failed.')
            return render_template('login-failed.html')
    else:
        logger.error('Authentication failed.')
        return render_template('login-failed.html')


@blueprint.route('/api/cognito/logout')
def cognito_callback_logout():
    logger.info('########### LOGOUT #########')
    redirect_url = util.config_reader.get_cognito_logout_redirect_uri()
    return redirect(redirect_url)


@blueprint.route('/api/logout', methods=['POST'])
def logout_user():
    logger.info('Log out !')
    try:
        token = request.headers.get('auth-token')
        username = escape(request.json.get('username'))
        UserToken.expire_token(token)

        if User.query.filter_by(username=username).first() is not None:
            user = User.query.filter_by(username=username).first()
            existing_token = UserToken.get_access_token(user.user_id)

            if existing_token is not None:
                existing_token_expired = (existing_token.token_expiration.timestamp() - datetime.now().timestamp()) <= 0
                
                if existing_token_expired:
                    logger.info('Successfully logged out !')
                    return jsonify({'message': "Logout successful.", username: username}), 200
                else:
                    
                    logger.info('Logout failed !')
                    return jsonify({'Error': 'Logout failed.'}), 422 

        logger.error('Invalid user name provided !')
        return jsonify({'Error': 'Invalid user name provided'}), 401
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Error occurred while expiring the token !')
        return jsonify({'error': str(e)}), 500


        # token_args = {
        #     "code": code,
        #     "grant_type": "authorization_code",
        #     "redirect_uri": util.config_reader.get_cognito_logout_uri(),
        #     "client_id": util.config_reader.get_cognito_client_id()
        # }
        # headers = {
        #     "Content-Type": "application/x-www-form-urlencoded"
        # }
        # logger.info(json.dumps(headers))
        # response = requests.post(util.config_reader.get_cognito_token_endpoint(),
        #                          data=token_args,
        #                          headers=headers)
        # status_code = response.status_code
        # logger.info(status_code)
        # if status_code == 200:
        # access_token_json = response.json()
        # access_token = access_token_json['access_token']
        # id_token = access_token_json['id_token']
        # refresh_token = access_token_json['refresh_token']
        # expires_in = access_token_json['expires_in']
        # user_info_header = {
        #     'Authorization': 'Bearer ' + access_token
        # }

        # user_info_response = requests.get(util.config_reader.get_cognito_userinfo_endpoint(), headers=user_info_header)
        # user_info_response_code = user_info_response.status_code
        # if user_info_response_code == 200:
        #     user_info_response_json = user_info_response.json()
        #     logger.info(user_info_response_json)

        #     aws_username = user_info_response_json['username']
        #     aws_username = aws_username.upper()
        #     if 'CILOGON' in aws_username:
        #         institution = user_info_response_json['custom:idp_name']
        #     elif 'GOOGLE' in aws_username:
        #         institution = 'google'
        #     else:
        #         institution = 'guest'
        #     email = user_info_response_json['email']
        #     given_name = user_info_response_json['given_name']
        #     family_name = user_info_response_json['family_name']
        #     full_name = given_name + " " + family_name

        #     if email is None:
        #         logger.error('Authentication failed.')
        #         return render_template('login-failed.html')

        #     names = email.split('@')
        #     username = names[0]
        #     logger.info(username)

        #     user_id = add_user(username, email, full_name, institution, aws_username)
        #     add_tokens(user_id, access_token, id_token, refresh_token)
        #     add_jupyter_user(user_id, username)
        #     logger.info(user_id)
        #     names = email.split('@')
        #     username = names[0]
        #     cadre_token = UserToken.get_access_token(user_id).token
        #     jupyter_token = JupyterUser.get_token(user_id, username)
        #     logger.info(cadre_token)
        #     logger.info(username)

        #     return redirect(cadre_dashboard_url + username + '&cadre_token=' + cadre_token + '&jupyter_token=' + jupyter_token)
        # else:
        #     logger.error('Authentication failed.')
        #     return render_template('login-failed.html')


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


