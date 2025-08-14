# app/__init__.py
import os
from dotenv import load_dotenv
from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail

load_dotenv()

db = SQLAlchemy()
mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Clave secreta para sesiones y mensajes flash
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')

    # ---------- Subidas de archivos (disco local) ----------
    base_dir = os.path.dirname(os.path.abspath(__file__))
    upload_dir = os.path.abspath(os.path.join(base_dir, "..", "uploads"))
    os.makedirs(upload_dir, exist_ok=True)

    app.config["UPLOAD_FOLDER"] = upload_dir
    app.config["ALLOWED_EXTENSIONS"] = {"pdf", "jpg", "jpeg", "png", "webp"}
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB

    # ---------- Inicializar extensiones ----------
    db.init_app(app)
    mail.init_app(app)

    # ---------- Registrar blueprint ----------
    from .routes import bp as routes_bp
    app.register_blueprint(routes_bp)

    # Importar modelos para que SQLAlchemy los reconozca
    from app import models

    return app

# Instancia global para WSGI / Render
app = create_app()
