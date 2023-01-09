# I add logging
import logging

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SECRET_KEY"] = "5791628bb0b13ce0c676dfde280ba245"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
# Get rid of annoying warning
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"


logging.basicConfig(
    level=logging.INFO,
    format=f"%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s",
)
