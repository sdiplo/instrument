from flask import Flask
from flask_login import LoginManager
from flask_mail import Mail
from config import Config
import psycopg2

# Инициализация расширений
login_manager = LoginManager()
mail = Mail()

# Функция создания приложения Flask
def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Настройка расширений
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'
    mail.init_app(app)

    # Подключение к базе данных PostgreSQL
    app.conn = psycopg2.connect(
        dbname=app.config['DB_NAME'],
        user=app.config['DB_USER'],
        password=app.config['DB_PASSWORD'],
        host=app.config['DB_HOST']
    )

    # Регистрация блюпринтов
    from .routes import main
    app.register_blueprint(main)

    return app


