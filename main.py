from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key='secret'

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Database Model - Single Table and row
class User(db.Model):
    # Class for User Model
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# Routes
@app.route('/')
def home():
    if "username" in session:
        return redirect(url_for)('dashboard.html')
    return render_template('index.html')

# Login Route
@app.route('/login', methods=['POST'])
def login():
    # Collect the data from the form
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

    # Check if the user exists in the database
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('home'))

# Register Route
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    user= User.query.filter_by(username=username).first()
    if user:
        return render_template('index.html', message='User Already Exists')
    else:
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = username
        return render_template('dashboard.html', message='User Created Successfully')

# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if "username" in session:
        return render_template('dashboard.html', username=session['username'])
    return redirect(url_for('home'))

# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))



if __name__ in "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)