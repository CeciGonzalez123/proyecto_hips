from flask import Flask
from hips.vistas import main

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = '1234'
    app.register_blueprint(main, url_prefix='/')
    return app

