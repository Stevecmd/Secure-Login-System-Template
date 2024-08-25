from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = 'secret'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Database Model - Single Table and row
class User(db.Model):
    """User Model

    Args:
        db (_type_): Model from SQL Alchemy

    Returns:
        string: Only check_password returns, else used to store user info
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        """Hashes the password and stores it in the password_hash field

        Args:
            password (str): The plain text password
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks the hashed password against the stored hash

        Args:
            password (str): The plain text password

        Returns:
            bool: True if the password matches, False otherwise
        """
        return check_password_hash(self.password_hash, password)


# Routes
@app.route('/')
def home():
    """Displays a Page based on the session of the current user

    Returns:
        html template: Returns the Dashboard or Index
    """
    if "username" in session:
        return redirect(url_for)('dashboard.html')
    return render_template('index.html')


# Login Route
@app.route('/login', methods=['POST'])
def login():
    """Confirms username and password in the database using the model

    Returns:
        html template: Directs the user to a page matching their login info
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

    # Check if the user exists in the database
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return redirect(
                url_for(
                    'home',
                    error='Invalid username or password'
                )
            )


# Register Route
@app.route('/register', methods=['POST'])
def register():
    """Registers a new user within the SQL Alchemy DB

    Returns:
        html template: Creates a session with the new user
    """
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user:
        return render_template('index.html', message='User Already Exists')
    else:
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = username
        return render_template('dashboard.html',
                               message='User Created Successfully'
                               )


# Dashboard Route
@app.route('/dashboard')
def dashboard():
    """Displays the dashboard if the user is logged in

    Returns:
        html template: Returns the Dashboard or redirects to Home
    """
    if "username" in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('home'))


# Logout Route
@app.route('/logout')
def logout():
    """Logs out the current user by clearing the session

    Returns:
        redirect: Redirects to the Home page
    """
    session.pop('username', None)
    return redirect(url_for('home'))


if __name__ in "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
