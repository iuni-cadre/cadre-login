import os, sys
from datetime import datetime

from flask import Flask, logging
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy_utils import database_exists, create_database

abspath = os.path.abspath(os.path.dirname(__file__))
cadre = os.path.dirname(abspath)
util = cadre + '/util'
sys.path.append(cadre)

import util.config_reader

app = Flask(__name__)
logger = logging.getLogger(__name__)

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

Base = declarative_base()


def create_tables():
    engine = create_engine(DB_URL)
    if not database_exists(engine.url):
        create_database(engine.url)
    db.create_all()
    db.session.commit()


class UserLogin(db.Model):
    __tablename__ = 'user_login'
    id = db.Column(db.Integer, primary_key=True)
    social_id = db.Column(db.String(64), nullable=False, unique=True)
    name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(64), nullable=True)
    institution = db.Column(db.String(128), nullable=True)
    login_count = db.Column(db.Integer, default=0)


class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    login_id = db.Column(db.Integer, ForeignKey(UserLogin.id))
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(255))
    email = db.Column(db.String(255))
    created_on = db.Column(db.DateTime)
    modified_on = db.Column(db.DateTime)
    created_by = db.Column(db.String(32))
    modified_by = db.Column(db.String(32), default=datetime.now())
    token = db.Column(db.String(256))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        logger.info('******* generate token ******** ')
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        dumps = s.dumps({'id': self.user_id})
        return dumps

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = User.query.get(data['id'])
        existing_tokens = user.token
        if existing_tokens is not None:
            if token in existing_tokens.values():
                return user
            else:
                return None
        return user

    @staticmethod
    def get_user(token):
        s = Serializer(app.config['SECRET_KEY'])
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
        all_roles_user = UserRole.query.filter_by(user_id=user_id)
        role_list = []
        if all_roles_user:
            for user in all_roles_user:
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