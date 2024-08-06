
# Flask_API

## Overview

This project is a Flask-based API for managing user accounts with JWT authentication, SQLAlchemy for ORM, and Flask-Restx for building RESTful APIs. The application supports user registration, login, password reset, and user management features.

## Table of Contents

- [Installation](#installation)
- [Database Migration](#database-migration)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
  - [User Registration](#user-registration)
  - [User Login](#user-login)
  - [Forget Password](#forget-password)
  - [Reset Password](#reset-password)
  - [User Profile](#user-profile)
  - [Update Profile](#update-profile)
  - [Get User Details](#get-user-details)
  - [Update User Details](#update-user-details)
  - [Delete User](#delete-user)
  - [Make Admin](#make-admin)
- [Security](#security)
- [License](#license)

## Getting Started

### Prerequisites

- Python 3.x
- PostgreSQL
- Git

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/noman1811048/flask_api
   cd flask_api
   ```

2. **Create and activate a virtual environment:**

   ```bash
   python -m venv venv
   source venv/bin/activate   # On Windows use `venv\Scripts\activate`
   ```

3. **Install the dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Set up PostgreSQL:**

   Create a PostgreSQL database and a user with appropriate privileges. Update the config.py file with your database connection details.

   ```python
   # config.py
   SQLALCHEMY_DATABASE_URI = 'postgresql://username:password@localhost/dbname'
   ```

5. **Initialize the database:**

   ```bash
   flask db init
   flask db migrate -m "Initial migration."
   flask db upgrade
   ```

### Configuration

The application requires several environment variables for configuration. These can be set in your environment at the root of your project file config.py. Below is a list of the necessary configuration variables:

```python
import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'YOUR_SECRET_KEY'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://postgres:password@localhost:PORT/DB_NAME'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_TOKEN_LOCATION = ['headers']
    JWT_HEADER_NAME = 'Authorization'
    JWT_HEADER_TYPE = 'Bearer'

    MAIL_SERVER = 'your_mail_server'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'your_gmail'
    MAIL_PASSWORD = 'your_mail_app password'
```

### Running the Application

1. **Start the Flask development server:**

   ```bash
   flask run
   ```
### Admin Feature

To create the first admin user, you need to run a Flask CLI command. This command should be executed after setting up the database and before running the application for the first time:

```bash
flask create-admin
```

This command will prompt you to enter the necessary details for the admin user, such as username, email, and password. Once created, this user will have full administrative privileges.

2. **API Documentation:**

   Once the server is running, you can access the API documentation at http://127.0.0.1:5000/swagger-ui.

## API Endpoints

### User Registration

Any user can register but initial role is "USER".

**POST** /user/register

**Request Body:**

```json
{
  "username": "user1",
  "first_name": "User",
  "last_name": "One",
  "email": "user1@example.com",
  "password": "password123"
}
```

**Response:**

```json
{
  "msg": "User registered successfully."
}
```

### User Login

**POST** /user/login

**Request Body:**

```json
{
  "username": "user1",
  "password": "password123"
}
```

**Response:**

```json
{
  "access_token": "your_jwt_access_token"
}
```

### Forget Password

**POST** /user/request-password-reset
First, go to your email and find a link that looks like this: http://127.0.0.1:5000/user/reset-password/3XvseRjDpxWINYhh0w0Mss8-8m4nrqYPZwFp-rCAX4s. Then, copy the last part of the URL (e.g., 3XvseRjDpxWINYhh0w0Mss8-8m4nrqYPZwFp-rCAX4s) and paste it into this endpoint: /user/reset-password/3XvseRjDpxWINYhh0w0Mss8-8m4nrqYPZwFp-rCAX4s.

**Request Body:**

```json
{
 "email": "user1@example.com"
}
```

**Response:**

```json
{
  "message": "If an account with that email exists, a password reset link has been sent."
}
```

### Reset Password

**POST** /user/reset-password/{token}

**Request Body:**

```json
{
  "token": "string",
  "new_password": "string"
}
```

**Response:**

```json
{
  "msg": "Password has been reset."
}
```

### Update User Details

A admin can update his own and users with role="USER".

**PUT** /api/user/<user_id>

**Headers:**

```http
Authorization: Bearer your_jwt_access_token
```

**Request Body:**

```json
{
  "username": "string",
  "email": "user@example.com",
  "first_name": "string",
  "last_name": "string",
  "active": true
}
```

**Response:**

```json
{
  "msg": "Updated Successfully."
}
```

### Delete User

The admin can delete only those with role="USER". The admin can't delete his own self and other admin.

**DELETE** /api/user/{user_id}

**Headers:**

```http
Authorization: Bearer your_jwt_access_token
```

**Response:**

```json
{
  "msg": "User deleted."
}
```

### Make User Admin

The admin can grant admin privileges to other users.

**PUT** /api/user/{user_id}/make_admin

**Headers:**

```http
Authorization: Bearer your_jwt_access_token
```

**Response:**

```json
{
  "msg": "User has been granted admin privileges."
}
```

## Project Structure

```
.
├── app
│   ├── __init__.py
│   ├── cli.py
│   ├── email.py
│   ├── models.py
│   ├── routes.py
│   ├── schemas.py
├── migrations
├── venv
├── .gitignore
├── config.py
├── requirements.txt
├── run.py
```

## Models

- **User**
  - id (Integer, Primary Key)
  - username (String, Unique)
  - first_name (String)
  - last_name (String)
  - password (String, Encrypted)
  - email (String, Unique)
  - role (Enum: Admin/User)
  - created_at (DateTime, default=datetime.utcnow)
  - updated_at (DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
  - active (Boolean, default=True)

## Security

- Passwords are encrypted.
- JWT tokens are used for authentication.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
