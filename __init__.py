from dotenv import load_dotenv
load_dotenv()
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail


mail = Mail()

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = 'main.login'

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.getcwd(), 'data.db')
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
    
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_USE_SSL'] = False
    mail.init_app(app)

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)

    from .routes import main
    app.register_blueprint(main)

    return app