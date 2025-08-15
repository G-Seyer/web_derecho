# app/__init__.py
import os
from pathlib import Path
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from dotenv import load_dotenv
from config import Config
from flask_login import LoginManager

# Cargar .env desde la raíz
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

db = SQLAlchemy()
mail = Mail()
login_manager = LoginManager()      # <-- nuevo

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')

    # Subidas
    base_dir = os.path.dirname(os.path.abspath(__file__))
    upload_dir = os.path.abspath(os.path.join(base_dir, "..", "uploads"))
    os.makedirs(upload_dir, exist_ok=True)
    app.config["UPLOAD_FOLDER"] = upload_dir
    app.config["ALLOWED_EXTENSIONS"] = {"pdf", "jpg", "jpeg", "png", "webp"}
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

    # Inicializar extensiones
    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)                # <-- nuevo
    login_manager.login_view = "routes.login"  # <-- adónde redirigir si no hay sesión

    # Registrar blueprint principal
    from .routes import bp as routes_bp
    app.register_blueprint(routes_bp)

    from app import models  # si tus modelos existen
    return app

app = create_app()
