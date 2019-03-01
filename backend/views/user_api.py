import json
import logging.config
import os
import sys
import traceback
from datetime import datetime

from flask import jsonify, request, escape, abort, Response, Blueprint

abspath = os.path.abspath(os.path.dirname(__file__))
parent = os.path.dirname(abspath)
util = parent + '/util'
sys.path.append(parent)

from .data_model import User, UserRole
from backend import db

blueprint = Blueprint('user_api', __name__)
logger = logging.getLogger('user_api')


@blueprint.route('/api/login', methods=['POST'])
def login_user():
    logger.info('Login user to the system !')
    try:
        username = escape(request.json.get('username'))
        password = escape(request.json.get('password'))
        if username is None or password is None:
            abort(400)  # missing arguments
        if User.query.filter_by(username=username).first() is not None:
            user = User.query.filter_by(username=username).first()
            if user.verify_password(password):
                token = user.generate_auth_token(600)
                user.token = token.decode('ascii')
                user.modified_on = datetime.now()
                db.session.commit()
                roles = UserRole.get_roles(user.user_id)
                logger.info('User %s logged in successfully !', username)
                return jsonify({'token': token.decode('ascii'), 'roles': roles, 'duration': 600, 'id': user.user_id})
            logger.info('Password incorrect for user : %s', username)
            abort(401)
        logger.info('Invalid user name : %s', username)
        return jsonify({'error': "Username not found"}), 401  # could not find username
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Error occurred while login user to system !')
        return jsonify({'error': str(e)}), 500


@blueprint.route('/api/logout', methods=['GET'])
def logout_user():
    logger.info('Logout User !')
    try:
        username = escape(request.json.get('username'))
        token = request.headers.get('auth-token')
        if User.query.filter_by(username=username).first() is not None:
            user = User.query.filter_by(username=username).first()
            saved_token = user.token
            if token == saved_token:
                user.token = None
                user.modified_on = datetime.now()
                db.session.commit()
                return jsonify({'username': username}), 200
            return jsonify({'Logout': 'Failed'}), 500
        return jsonify({'Logout': 'Failed, Invalid username'}), 401
    except Exception as e:
        logger.error('Error occurred while log out user !')
        return jsonify({'error': str(e)}), 500


@blueprint.route('/api/authenticate-token', methods=['POST'])
def authenticate_token():
    logger.info('Authenticate token !')
    try:
        token = request.headers.get('auth-token')
        logger.info(token)
        username = escape(request.json.get('username'))
        logger.info(username)
        if User.query.filter_by(username=username).first() is not None:
            user = User.query.filter_by(username=username).first()
            saved_token = user.token
            logger.info(saved_token)
            if token != saved_token:
                logger.error('Invalid token provided !')
                return jsonify({'Error': 'Invalid token'}), 401
            else:
                user = User.verify_auth_token(token)
                if user is not None:
                    roles = UserRole.get_roles(user.user_id)
                    logger.info(roles)
                    logger.info('User token authenticated successfully !')
                    success_message = {
                        'success': True,
                        'roles': roles
                    }
                    resp = Response(response=json.dumps(success_message),
                                    mimetype="application/json",
                                    status=200,
                                    headers={"x-cadre-auth-token": user.token,
                                             "Access-Control-Expose-Headers": "x-cadre-auth-token"})
                    return resp
                logger.info('Invalid user token !')
                error_message = "{'Error': 'Invalid user token'}"
                resp = Response(response=error_message,
                                mimetype="application/json",
                                status=401,
                                headers={"x-cadre-auth-token": user.token,
                                         "Access-Control-Expose-Headers": "x-cadre-auth-token"})
                return resp
        logger.error('Invalid user name provided !')
        return jsonify({'Error': 'Invalid user name'}), 401
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Error occurred while authenticate token !. Error is ' + str(e))
        return jsonify({'error': str(e)}), 500


@blueprint.route('/api/renew-token', methods=['POST'])
def renew_token():
    logger.info('Renew token !')
    try:
        token = request.headers.get('auth-token')
        username = escape(request.json.get('username'))
        if User.query.filter_by(username=username).first() is not None:
            user = User.query.filter_by(username=username).first()
            existing_token = user.token
            if existing_token is not None:
                user = User.verify_auth_token(token)
                if user is not None:
                    token = user.token
                    logger.info('Authentication token renewed successfully !')
                    return jsonify({'token': token.decode('ascii'), 'duration': 600})
                logger.info('Invalid or expired user token !')
                return jsonify({'Error': 'Invalid or expired user token'}), 401
        logger.error('Invalid user name provided !')
        return jsonify({'Error': 'Invalid user name provided'}), 401
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Error occurred while renewing the token !')
        return jsonify({'error': str(e)}), 500


@blueprint.route('/api/current-user-info', methods=['GET'])
def get_user_info():
    logger.info('Get Current User Info !')
    try:
        token = request.headers.get('auth-token')
        user = User.verify_auth_token(token)
        if user is not None:
            logger.info('User retrieved successfully !')
            roles = UserRole.get_roles(user.user_id)
            resp_message = {'username': user.username,
                            'email': user.email,
                            'roles': roles}
            resp = Response(response=json.dumps(resp_message),
                            mimetype="application/json",
                            status=200,
                            headers={"x-cadre-auth-token": user.token,
                                     "Access-Control-Expose-Headers": "x-cadre-auth-token"})
            return resp
        logger.info('Unable to retrieve the user !')
        return False
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Error occurred while retrieving user info !')
        return jsonify({'error': str(e)}), 500


@blueprint.route('/api/user/create', methods=['POST'])
def new_user():
    logger.info('Register new user !')
    try:
        username = escape(request.json.get('username'))
        password = escape(request.json.get('password'))
        email = escape(request.json.get('email'))
        roles = escape(request.json.get('roles'))
        login_id = request.json.get('loginid')
        if username is None or password is None:
            logger.info('Either username or password is missing !')
            abort(400)  # missing arguments
        if User.query.filter_by(username=username).first() is not None:
            logger.info('Username already exists in the system !')
            return jsonify({'error': 'Username already exists in the system !'}), 409
        user = User(username=username, email=email)
        user.hash_password(password)
        user.email = email
        user.created_on = datetime.now()
        db.session.add(user)
        db.session.commit()
        user_id = user.user_id
        # add roles
        if ',' in roles:
            roles_split = roles.split(',')
            if roles_split:
                for role in roles_split:
                    user_role = UserRole(user_id=user_id, project_id=1, role=role)
                    db.session.add(user_role)
                    db.session.commit()
        else:
            user_role = UserRole(user_id=user_id, project_id=1, role=roles)
            user_role.created_on = datetime.now()
            user_role.created_by = user.user_id
            db.session.add(user_role)
            db.session.commit()
        logger.info('New user %s created successfully !', username)
        return jsonify({'username': user.username}), 200
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Error occurred while registering new user !')
        return jsonify({'error': str(e)}), 500


@blueprint.route('/api/user', methods=['GET'])
def get_all_users():
    logger.info('Get all users !')
    try:
        token = request.headers.get('auth-token')
        user = User.verify_auth_token(token)
        if user is not None:
            logger.info("User token verified")
            all_users = User.query.all()
            user_name_list = []
            for user in all_users:
                user_name_list.append(user.username)
            if user_name_list:
                logger.info('Successfully retrieved all the users !')
                resp_json = {'users': user_name_list}
                resp = Response(response=json.dumps(resp_json),
                                mimetype="application/json",
                                status=200,
                                headers={"x-cadre-auth-token": user.token,
                                         "Access-Control-Expose-Headers": "x-cadre-auth-token"})
                return resp
            resp_json = {'users': 0}
            resp = Response(response=json.dumps(resp_json),
                            mimetype="application/json",
                            status=200,
                            headers={"x-cadre-auth-token": user.token,
                                     "Access-Control-Expose-Headers": "x-cadre-auth-token"})
            return resp
        logger.info('Unable to validate user token !')
        return jsonify({'status': 'unable to validate user token'}), 401
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Error occurred while getting all the users !')
        return jsonify({'error': str(e)}), 500


@blueprint.route('/api/user/<string:username>/update', methods=['POST'])
def update_user(username):
    logger.info('Update user !')
    try:
        token = request.headers.get('auth-token')
        user = User.verify_auth_token(token)
        if user is not None:

            roles = UserRole.get_roles(user.user_id)
            role_found = False
            if roles:
                for role in roles:
                    if role == 'admin':
                        role_found = True
                    elif role == 'user-manager':
                        role_found = True
                    elif role == 'testing':
                        role_found = True
            if role_found or user.username == username:
                password = escape(request.json.get('password'))
                confirm_password = request.json.get('confirm_password')
                email = escape(request.json.get('email'))
                roles = escape(request.json.get('roles'))
                if username is None:
                    logger.info('Either username is missing !')
                    abort(400)  # missing arguments

                if User.query.filter_by(username=username).first() is not None:
                    user = User.query.filter_by(username=username).first()

                    # if updating password
                    if password is not None and password != "" and password != "None":
                        # password must match confirm password or it fails
                        if password == confirm_password:
                            user.hash_password(password)
                        else:
                            logger.info('Password and confirm password do not match!')
                            return jsonify({'error': 'password and confirm password must match'}), 422
                    else:
                        logger.info(' Not updating password. ')

                    # if user.verify_password(password):
                    user.email = email
                    user.modified_on = datetime.now()
                    user.modified_by = user.user_id
                    db.session.flush()
                    # get roles
                    existing_roles_count = UserRole.query.filter_by(user_id=user.user_id).count()
                    role_list = ''

                    # remove all existing roles
                    if existing_roles_count > 0:
                        UserRole.query.filter_by(user_id=user.user_id).delete()
                        db.session.commit()
                        # existing_roles = ProjectUserRole.query.filter_by(user_id=user.user_id)
                        # for existing_role in existing_roles:
                        # role_list += existing_role.role + ','

                    # re add all submitted roles
                    roles_split = roles.split(',')
                    if roles_split:
                        for new_role in roles_split:
                            # if new_role not in role_list:
                            user_role = UserRole(user_id=user.user_id, project_id=1, role=new_role)
                            user_role.created_by = user.user_id
                            user_role.created_on = datetime.now()
                            db.session.add(user_role)
                            db.session.commit()

                    logger.info('User info updated successfully !')
                    response_json = {'username': user.username}
                    resp = Response(response=json.dumps(response_json),
                                    mimetype="application/json",
                                    status=201,
                                    headers={"x-cadre-auth-token": user.token,
                                             "Access-Control-Expose-Headers": "x-cadre-auth-token"})
                    return resp
                    # logger.info('Unable to validate password !')
                    # return jsonify({'error': 'Password validation failed'}), 401
            else:
                logger.info('Logged in user unable to edit user ' + username + ' !')
                return jsonify({'error': 'lack permissions to update user'}), 401
        else:
            logger.info('Unable to validate user token !')
            return jsonify({'status': 'unable to validate user token'}), 401
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Error occurred while updating user !')
        return jsonify({'error': str(e)}), 500


@blueprint.route('/api/user/<string:username>/delete', methods=['POST'])
def delete_user(username):
    logger.info('Delete user !')
    try:
        global role_found
        token = request.headers.get('auth-token')
        user = User.verify_auth_token(token)
        if user is not None:
            roles = UserRole.get_roles(user.user_id)
            if roles:
                for role in roles:
                    if role == 'admin':
                        role_found = True
                    elif role == 'user-manager':
                        role_found = True
                    elif role == 'testing':
                        role_found = True
            if role_found:
                UserRole.query.filter_by(user_id=user.user_id).delete()
                User.query.filter_by(user_id=user.user_id).delete()
                db.session.commit()
                user_response = {'Success': True}
                resp = Response(response=json.dumps(user_response),
                                mimetype="application/json",
                                status=200,
                                headers={"x-cadre-auth-token": user.token,
                                         "Access-Control-Expose-Headers": "x-cadre-auth-token"})
        logger.info('Unable to validate user token !')
        return jsonify({'status': 'unable to validate user token'}), 401
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Error occurred while deleting user !')
        return jsonify({'error': str(e)}), 500


@blueprint.route('/api/user/<string:username>', methods=['GET'])
def get_user(username):
    logger.info('Get user !')
    try:
        global role_found
        token = request.headers.get('auth-token')
        user = User.verify_auth_token(token)
        if user is not None:
            role_found = False
            roles = UserRole.get_roles(user.user_id)
            if roles:
                for role in roles:
                    if role == 'admin':
                        role_found = True
                    elif role == 'user-manager':
                        role_found = True
                    elif role == 'testing':
                        role_found = True
            if role_found:
                new_user = User.query.filter_by(username=username).first()
                if new_user is not None:
                    new_roles = UserRole.get_roles(new_user.user_id)
                    user_response = {'username': username, 'user_id': new_user.user_id, 'roles': new_roles,
                                     'email': new_user.email}
                    resp = Response(response=json.dumps(user_response),
                                    mimetype="application/json",
                                    status=200,
                                    headers={"x-cadre-auth-token": user.token,
                                             "Access-Control-Expose-Headers": "x-cadre-auth-token"})
                    return resp
                else:
                    logger.info('Unable to find user ' + username + ' !')
                    return jsonify({'status': 'user not found'}), 404
        logger.info('Unable to validate user token !')
        return jsonify({'status': 'unable to validate user token'}), 401
    except Exception as e:
        traceback.print_tb(e.__traceback__)
        logger.error('Error occurred while getting user !')
        return jsonify({'error': str(e)}), 500