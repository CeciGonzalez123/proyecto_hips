from flask import Flask
from flask_login import LoginManager, UserMixin
from hips.vistas import main

app = Flask(__name__)
app.config['SECRET_KEY'] = '1234'

# Registro del blueprint
app.register_blueprint(main, url_prefix='/')

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'main.login'

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

if __name__ == "__main__":
    app.run(debug=True)



