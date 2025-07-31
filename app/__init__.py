from flask import Flask

def create_app():
    app = Flask(__name__)

    # Importar y registrar blueprint
    from .routes import main
    app.register_blueprint(main)

    return app
