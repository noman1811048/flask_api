import click
from flask.cli import with_appcontext
from app import db
from app.models import User, UserRole

@click.command('create-admin')
@click.option('--username', prompt=True)
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
@click.option('--email', prompt=True)
@click.option('--first-name', prompt=True)
@click.option('--last-name', prompt=True)
@with_appcontext
def create_admin(username, password, email, first_name, last_name):
    user = User(
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        role=UserRole.ADMIN
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    click.echo(f"Admin user {username} created successfully.")

# Add more custom commands here if needed