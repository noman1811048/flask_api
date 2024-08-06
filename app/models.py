from app import db, bcrypt
from datetime import datetime, timedelta
from enum import Enum
import secrets

class UserRole(Enum):
    ADMIN = 'Admin'
    USER = 'User'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.USER)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    active = db.Column(db.Boolean, nullable=False, default=True)
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)

    def __init__(self, username, first_name, last_name, email, role=UserRole.USER):
        self.username = username
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.role = role

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def generate_reset_token(self):
        self.reset_token = secrets.token_urlsafe(32)
        self.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
        db.session.commit()

    def verify_reset_token(self, token):
        if token != self.reset_token or self.reset_token_expiration < datetime.utcnow():
            return False
        return True

    def reset_password(self, new_password):
        self.set_password(new_password)
        self.reset_token = None
        self.reset_token_expiration = None
        db.session.commit()
