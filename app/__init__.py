from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_smorest import Api
from flask_mail import Mail
import logging
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
ma = Marshmallow()
bcrypt = Bcrypt()
mail = Mail()

def create_app(config_class=None):
    app = Flask(__name__)
    
    if config_class is None:
        from config import Config
        config_class = Config
    
    app.config.from_object(config_class)
    logging.basicConfig(level=logging.INFO)
    
    # Flask-SMOREST configuration
    app.config["API_TITLE"] = "User Management API"
    app.config["API_VERSION"] = "v1"
    app.config["OPENAPI_VERSION"] = "3.0.2"
    app.config["OPENAPI_URL_PREFIX"] = "/"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    
    # JWT Authorization configuration for Swagger UI
    app.config["API_SPEC_OPTIONS"] = {
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                }
            }
        },
        "security": [{"bearerAuth": []}]
    }
    
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    ma.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    CORS(app)
    
    api = Api(app)
    
    from app.routes import user_blp
    api.register_blueprint(user_blp)
 
    from app.cli import create_admin
    app.cli.add_command(create_admin)
    
    return app
