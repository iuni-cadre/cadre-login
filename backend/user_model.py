import os, sys
from flask import Flask, redirect, url_for, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user,current_user

abspath = os.path.abspath(os.path.dirname(__file__))
cadre = os.path.dirname(abspath)
util = cadre + '/util'
sys.path.append(cadre)

import util.config_reader

app = Flask(__name__)
lm = LoginManager(app)
lm.login_view = 'index'

app.config['SECRET_KEY'] = 'test key'
url = util.config_reader.get_cadre_db_hostname() + ':' + util.config_reader.get_cadre_db_port()
DB_URL = 'postgres://{user}:{pw}@{url}/{db}'.format(user=util.config_reader.get_cadre_db_username(),
                                                    pw=util.config_reader.get_cadre_db_pwd(),
                                                    url=url,
                                                    db=util.config_reader.get_cadre_db_name())
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URL
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    social_id = db.Column(db.String(64), nullable=False, unique=True)
    name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(64), nullable=True)
    institution = db.Column(db.String(128), nullable=True)


@lm.user_loader
def load_user(id):
    return User.query.get(int(id))