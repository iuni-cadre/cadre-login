import json
import os, sys
from datetime import datetime, timedelta

import requests
from flask import Blueprint, logging, current_app
from sqlalchemy import ForeignKey
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database

abspath = os.path.abspath(os.path.dirname(__file__))
cadre = os.path.dirname(abspath)
util = cadre + '/util'
sys.path.append(cadre)

blueprint = Blueprint('data_model', __name__)
logger = logging.getLogger('data_model')

from backend import db, DB_URL
import util.config_reader


def create_tables():
    engine = create_engine(DB_URL)
    if not database_exists(engine.url):
        create_database(engine.url)
    db.create_all()
    db.session.commit()
    logger.info("Database initialized...")


class UserLogin(db.Model):
    __tablename__ = 'user_login'
    id = db.Column(db.Integer, primary_key=True)
    social_id = db.Column(db.String(128), nullable=False, unique=True)
    name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128), nullable=True)
    institution = db.Column(db.String(128), nullable=True)
    login_count = db.Column(db.Integer, default=0)


class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    login_id = db.Column(db.Integer, ForeignKey(UserLogin.id))
    username = db.Column(db.String(128), index=True)
    password_hash = db.Column(db.String(255))
    aws_username = db.Column(db.String(256))
    email = db.Column(db.String(255))
    created_on = db.Column(db.DateTime)
    modified_on = db.Column(db.DateTime)
    created_by = db.Column(db.String(128))
    modified_by = db.Column(db.String(128), default=datetime.now())

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)


class UserToken(db.Model):
    __tablename__ = 'user_token'
    user_id = db.Column(db.Integer, ForeignKey(User.user_id), primary_key=True)
    type = db.Column(db.String(128), primary_key=True)
    token = db.Column(db.String(255))
    token_expiration = db.Column(db.DateTime)

    def token_expiration_for_access_id_token(self):
        self.token_expiration = datetime.now() + timedelta(minutes=60)
        db.session.commit()
        return self.token_expiration

    def token_expiration_for_refresh_token(self):
        self.token_expiration = datetime.now() + timedelta(days=30)
        db.session.commit()
        return self.token_expiration

    def get_access_token(user_id):
        user = UserToken.query.filter_by(user_id=user_id, type='access').first()
        if user:
            return user
        return None

    def get_id_token(user_id):
        user = UserToken.query.filter_by(user_id=user_id, type='id').first()
        if user:
            return user
        return None

    def get_refresh_token(user_id):
        user = UserToken.query.filter_by(user_id=user_id, type='refresh').first()
        if user:
            return user
        return None

    @staticmethod
    def verify_auth_token(token):
        logger.info('******* verify token ******** ')
        try:
            access_token = UserToken.query.filter_by(token=token,type='access').first()
            access_token_expired = (access_token.expires_in.timestamp() - datetime.now().timestamp()) <= 0
            user_id = access_token.user_id
            refresh_token = access_token.get_refresh_token(user_id)
            id_token = access_token.get_id_token(user_id)
            refresh_token_expired = (refresh_token.expires_in.timestamp() - datetime.now().timestamp()) <= 0

            if access_token_expired and not refresh_token_expired:
                # try to get new access token and id token
                token_args = {
                    "grant_type": "refresh_token",
                    "redirect_uri": util.config_reader.get_cognito_redirect_uri(),
                    "client_id": util.config_reader.get_cognito_client_id(),
                    "refresh_token": refresh_token.token
                }
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded"
                }
                logger.info(json.dumps(headers))
                response = requests.post(util.config_reader.get_cognito_token_endpoint(),
                                         data=token_args,
                                         headers=headers)
                status_code = response.status_code
                logger.info(status_code)
                if status_code == 200:
                    refresh_token_response = response.json()
                    new_access_token = refresh_token_response['access_token']
                    new_id_token = refresh_token_response['id_token']
                    access_token.token = new_access_token
                    access_token.type = 'access'
                    access_token.token_expiration_for_access_id_token()
                    id_token.token = new_id_token
                    id_token.type = 'id'
                    id_token.token_expiration_for_access_id_token()
            elif refresh_token_expired:
                logger.info('Refresh token is expired. User needs to log back')
                return None
            else:
                return access_token
        except Exception:
            logger.info("Error")
            return None

    @staticmethod
    def get_user(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user_id = User.query.get(data['id'])
        user = User.query.filter_by(id=user_id).first()
        if user is not None:
            return user
        return None


class UserRole(db.Model):
    __tablename__ = 'user_role'
    user_id = db.Column(db.Integer, ForeignKey(User.user_id), primary_key=True)
    role = db.Column(db.String(255), primary_key=True)

    def get_roles(user_id):
        all_roles_user_count = UserRole.query.filter_by(user_id=user_id).count()
        role_list = []
        if all_roles_user_count > 0:
            all_roles = UserRole.query.filter_by(user_id=user_id)
            for user in all_roles:
                role_list.append(user.role)
            return role_list


class UserTeam(db.Model):
    __tablename__ = 'user_team'
    user_id = db.Column(db.Integer, ForeignKey(User.user_id), primary_key=True)
    team = db.Column(db.String(255), primary_key=True)

    def get_teams(user_id):
        all_teams_user = UserTeam.query.filter_by(user_id=user_id)
        team_list = []
        if all_teams_user:
            for team_user in all_teams_user:
                team_list.append(team_user.team)
            return team_list


class JupyterUser(db.Model):
    __tablename__ = 'jupyter_user'
    user_id = db.Column(db.Integer, ForeignKey(User.user_id), primary_key=True)
    j_username = db.Column(db.String(255), primary_key=True)
    j_pwd = db.Column(db.String(255))
    j_token = db.Column(db.String(255))

    def get_token(user_id,username):
        jupyter_user = JupyterUser.query.filter_by(user_id=user_id, j_username=username).first()
        if jupyter_user:
            return jupyter_user.j_token
        return None


class UserJob(db.Model):
    __tablename__ = 'user_job'
    j_id = db.Column(db.String(255), primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey(User.user_id))
    sns_message_id = db.Column(db.String(255))
    s3_location = db.Column(db.String(255))
    job_status = db.Column(db.String(255))
    created_on = db.Column(db.DateTime)
    last_updated = db.Column(db.DateTime)
