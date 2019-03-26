import os, sys
from datetime import datetime

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
    email = db.Column(db.String(255))
    created_on = db.Column(db.DateTime)
    modified_on = db.Column(db.DateTime)
    created_by = db.Column(db.String(128))
    modified_by = db.Column(db.String(128), default=datetime.now())
    token = db.Column(db.String(256))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        logger.info('******* generate token ******** ')
        secret_key = current_app.config['SECRET_KEY']
        s = Serializer(secret_key, expires_in=expiration)
        dumps = s.dumps({'id': self.user_id})
        return dumps

    def get_token(user_id,username):
        user = User.query.filter_by(user_id=user_id,username=username).first()
        if user:
            return user.token
        return None

    @staticmethod
    def verify_auth_token(token):
        logger.info('******* verify token ******** ')
        secret_key = current_app.config['SECRET_KEY']
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
            user_id = data['id']
            logger.info(user_id)
            user = User.query.get(user_id)
            return user
        except SignatureExpired:
            logger.info("Signature expired")
            return None  # valid token, but expired
        except BadSignature:
            logger.info("Bad Signature")
            return None  # invalid token

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
        jupyter_user = JupyterUser.query.filter_by(user_id=user_id,j_username=username).first()
        if jupyter_user:
            return jupyter_user.token
        return None