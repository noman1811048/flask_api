from app import create_app, db

app = create_app()  # Now we don't need to pass any arguments

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)