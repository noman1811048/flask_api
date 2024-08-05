import logging
from flask.views import MethodView
from flask_smorest import Blueprint, abort
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from marshmallow import Schema, fields
from app.models import User, UserRole
from app import db, bcrypt
from functools import wraps
from flask import current_app, url_for
from flask_mail import Message
from app import mail

user_blp = Blueprint(
    'users', 'users', url_prefix='/user',
    description='Operations on users'
)

class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True)
    email = fields.Email(required=True)
    password = fields.Str(required=True, load_only=True)
    first_name = fields.Str(required=True)
    last_name = fields.Str(required=True)
    role = fields.Str(dump_only=True)
    active = fields.Boolean()

class UserLoginSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)

class PasswordResetRequestSchema(Schema):
    email = fields.Email(required=True)

class PasswordResetSchema(Schema):
    token = fields.Str(required=True)
    new_password = fields.Str(required=True)

def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user or user.role != UserRole.ADMIN:
            abort(403, message="Admin access required")
        return fn(*args, **kwargs)
    return wrapper

def send_password_reset_email(user):
    token = user.generate_reset_token()
    reset_url = url_for('users.ResetPassword', token=token, _external=True)
    msg = Message('Password Reset Request',
                  sender=current_app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:

{reset_url}

If you did not make this request then simply ignore this email and no changes will be made.

This link is valid for 1 hour.
'''
    mail.send(msg)

@user_blp.route('/register')
class UserRegister(MethodView):
    @user_blp.arguments(UserSchema)
    @user_blp.response(201, UserSchema)
    def post(self, user_data):
        try:
            user = User(
                username=user_data['username'],
                email=user_data['email'],
                first_name=user_data['first_name'],
                last_name=user_data['last_name']
            )
            user.set_password(user_data['password'])
            db.session.add(user)
            db.session.commit()
            return user, 201
        except Exception as e:
            db.session.rollback()
            abort(500, message=f"An error occurred while registering the user: {str(e)}")

@user_blp.route('/login')
class UserLogin(MethodView):
    @user_blp.arguments(UserLoginSchema)
    def post(self, login_data):
        user = User.query.filter_by(username=login_data['username']).first()
        if user and user.active and bcrypt.check_password_hash(user.password, login_data['password']):
            access_token = create_access_token(identity=user.id)
            return {"access_token": access_token}, 200
        abort(401, message="Invalid credentials or inactive account.")

        
@user_blp.route('/profile')
class UserProfile(MethodView):
    @jwt_required()
    @user_blp.response(200, UserSchema(exclude=["password"]))
    @user_blp.doc(security=[{"bearerAuth": []}])
    def get(self):
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        return user

    @jwt_required()
    @user_blp.arguments(UserSchema(partial=True, exclude=["password", "role"]))
    @user_blp.response(200, UserSchema(exclude=["password"]))
    @user_blp.doc(security=[{"bearerAuth": []}])
    def put(self, user_data):
        user_id = get_jwt_identity()
        user = User.query.get_or_404(user_id)
        for key, value in user_data.items():
            setattr(user, key, value)
        db.session.commit()
        return user
    
@user_blp.route('/forgot-password')
class ForgotPassword(MethodView):
    @user_blp.arguments(PasswordResetRequestSchema)
    def post(self, reset_data):
        user = User.query.filter_by(email=reset_data['email']).first()
        if user:
            try:
                send_password_reset_email(user)
                return {"message": "If an account with that email exists, a password reset link has been sent."}, 200
            except Exception as e:
                logging.error(f"Error in forgot password process: {str(e)}")
                return {"message": "An error occurred while processing your request. Please try again later."}, 500
        else:
            logging.info(f"Password reset requested for non-existent email: {reset_data['email']}")
        return {"message": "If an account with that email exists, a password reset link has been sent."}, 200

@user_blp.route('/reset-password/<token>')
class ResetPassword(MethodView):
    @user_blp.arguments(PasswordResetSchema)
    def post(self, reset_data, token):
        user = User.query.filter_by(reset_token=token).first()
        if user and user.verify_reset_token(token):
            user.set_password(reset_data['new_password'])
            user.clear_reset_token()
            db.session.commit()
            return {"message": "Password has been reset successfully."}, 200
        abort(400, message="Invalid or expired token.")

@user_blp.route('/')
class UserList(MethodView):
    @admin_required
    @user_blp.response(200, UserSchema(many=True, exclude=["password"]))
    @user_blp.doc(security=[{"bearerAuth": []}])
    def get(self):
        users = User.query.all()
        return users

@user_blp.route('/<int:user_id>')
class UserResource(MethodView):
    @jwt_required()
    @user_blp.response(200, UserSchema(exclude=["password"]))
    @user_blp.doc(security=[{"bearerAuth": []}])
    def get(self, user_id):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        if current_user.role == UserRole.ADMIN or current_user_id == user_id:
            user = User.query.get_or_404(user_id)
            return user
        abort(403, message="Access denied")

    @admin_required
    @user_blp.arguments(UserSchema(partial=True, exclude=["password"]))
    @user_blp.response(200, UserSchema(exclude=["password"]))
    @user_blp.doc(security=[{"bearerAuth": []}])
    def put(self, user_data, user_id):
        user_to_update = User.query.get_or_404(user_id)
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if user_to_update.role == UserRole.ADMIN and current_user.id != user_to_update.id:
            abort(403, message="Cannot modify other admin users")

        for key, value in user_data.items():
            if key not in ['id', 'password', 'role']:  # Allow updating 'active' field
                setattr(user_to_update, key, value)

        db.session.commit()
        return user_to_update

    @admin_required
    @user_blp.response(204)
    @user_blp.doc(security=[{"bearerAuth": []}])
    def delete(self, user_id):
        user = User.query.get_or_404(user_id)
        if user.role == UserRole.ADMIN:
            abort(403, message="Cannot delete other admin users")
        db.session.delete(user)
        db.session.commit()
        return "", 204

@user_blp.route('/<int:user_id>/make-admin')
class MakeAdmin(MethodView):
    @admin_required
    @user_blp.response(200, UserSchema(exclude=["password"]))
    @user_blp.doc(security=[{"bearerAuth": []}])
    def put(self, user_id):
        user = User.query.get_or_404(user_id)
        if user.role == UserRole.ADMIN:
            abort(400, message="User is already an admin.")
        user.role = UserRole.ADMIN
        db.session.commit()
        return {"message": f"User {user.username} has been made an admin.", "user": UserSchema(exclude=["password"]).dump(user)}, 200