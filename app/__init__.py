from dotenv import load_dotenv
load_dotenv()
from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail

db = SQLAlchemy()
mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    mail.init_app(app)

    from app.routes import main
    app.register_blueprint(main)

    from app import models  # al final de create_app(), antes de return app

    return app

# 🔹 Instancia global de la aplicación para Gunicorn
app = create_app()