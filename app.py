from flask import Flask, render_template, request, redirect, session, url_for
from flask_bcrypt import Bcrypt
import mysql.connector

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Required for session management
bcrypt = Bcrypt(app)

# MySQL Database Connection
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="9090",
    database="finance_tracker"
)

cursor = db.cursor()

# SQL Queries
def get_user_by_username(username):
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    return cursor.fetchone()

def get_user_id(username):
    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    return cursor.fetchone()

def insert_user(username, hashed_password):
    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
    db.commit()

def insert_transaction(transaction_type, amount, description, user_id):
    cursor.execute("INSERT INTO transactions (type, amount, description, user_id) VALUES (%s, %s, %s, %s)", 
                   (transaction_type, amount, description, user_id))
    db.commit()

def get_user_transactions(user_id):
    cursor.execute("SELECT * FROM transactions WHERE user_id = %s", (user_id,))
    return cursor.fetchall()

def get_income(user_id):
    cursor.execute("SELECT SUM(amount) FROM transactions WHERE type = 'Income' AND user_id = %s", (user_id,))
    return cursor.fetchone()[0] or 0

def get_expenses(user_id):
    cursor.execute("SELECT SUM(amount) FROM transactions WHERE type = 'Expense' AND user_id = %s", (user_id,))
    return cursor.fetchone()[0] or 0

# Home route (redirect to login if not authenticated)
@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Get user details
    user = get_user_id(session['username'])
    user_id = user[0] if user else None

    # Fetch family members
    cursor.execute("SELECT * FROM family_members WHERE user_id = %s", (user_id,))
    family_members = cursor.fetchall()

    # Fetch transactions for each family member
    transactions = {}
    for member in family_members:
        member_id = member[0]
        cursor.execute("SELECT * FROM transactions WHERE member_id = %s", (member_id,))
        transactions[member_id] = cursor.fetchall()

    # Pass the username and other details to the template
    return render_template('index.html', username=session['username'], family_members=family_members, transactions=transactions)

# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user_by_username(username)

        if user and bcrypt.check_password_hash(user[2], password):
            session['username'] = username  # Store username in session
            return redirect(url_for('index'))  # Redirect to home page
        else:
            return "Login failed. Check your username and password."

    return render_template('login.html')

# User logout route
@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from session
    return redirect(url_for('login'))  # Redirect to login page

# Add transaction route for family members
@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = get_user_id(session['username'])
    user_id = user[0] if user else None

    transaction_type = request.form['type']
    amount = request.form['amount']
    
    # Select description or allow custom input
    selected_description = request.form['description-select']
    if selected_description == 'Other':
        description = request.form['description']
    else:
        description = selected_description
    
    member_id = request.form['member_id']  # Family member selected from the dropdown

    cursor.execute("INSERT INTO transactions (type, amount, description, member_id) VALUES (%s, %s, %s, %s)",
                   (transaction_type, amount, description, member_id))
    db.commit()

    return redirect(url_for('index'))

# Add family member route
@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'username' not in session:  # Ensure the head of the family is logged in
        return redirect(url_for('login'))

    if request.method == 'POST':
        member_name = request.form['name']
        user = get_user_id(session['username'])
        user_id = user[0] if user else None

        cursor.execute("INSERT INTO family_members (name, user_id) VALUES (%s, %s)", (member_name, user_id))
        db.commit()
        return redirect(url_for('index'))

    return render_template('add_member.html')

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        insert_user(username, hashed_password)

        return redirect(url_for('login'))

    return render_template('register.html')

if __name__ == "__main__":
    app.run(debug=True)
