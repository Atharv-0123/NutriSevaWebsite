from flask import Flask, render_template, request, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.secret_key = 'secret_key'

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

# Create User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

# Routes for login and signup
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        username_email = request.form['username_email']
        password = request.form['password']

        # Query database for user
        user = User.query.filter((User.username == username_email) | (User.email == username_email)).first()

        # Check if user exists and password is valid
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
            # Store user ID in session
            session['user_id'] = user.id
            return redirect(url_for('profile'))
        else:
            # Show error message
            return render_template('login.html', error='Invalid username/email or password')

    # Render login form
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create new user
        user = User(username=username, email=email, password=hashed_password)

        # Add user to database
        db.session.add(user)
        db.session

@app.route('/')
def home():
    return render_template('index.html')


if __name__ == "__main__":
    app.run(debug=True)