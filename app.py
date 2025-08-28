from flask import Flask, render_template, request, redirect, session
from pymongo import MongoClient
from datetime import datetime

app = Flask(__name__)
app.secret_key = "something"

MONGO_URI = "mongodb+srv://interestng:aviralthebest!@financecluster.t3exzgo.mongodb.net/?retryWrites=true&w=majority&appName=FinanceCluster"
client = MongoClient(MONGO_URI)
db = client.finance_db

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        if db.users.find_one({"username": request.form['username']}):
            return "user exists"
        db.users.insert_one({"username": request.form['username'], "password": request.form['password']})
        return redirect('/login')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = db.users.find_one({"username": request.form['username']})
        if user and user['password'] == request.form['password']:
            session['user'] = user['username']
            return redirect('/dashboard')
        return "invalid creds"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

@app.route('/dashboard')
# todo: add password hashing maybe?
def dashboard():
    if 'user' not in session:
        return redirect('/login')

    username = session['user']
    transactions = list(db.transactions.find({"username": username}))

    income = sum(t['amount'] for t in transactions if t['type'] == 'income')
    expenses = sum(t['amount'] for t in transactions if t['type'] == 'expense')

    return render_template('dashboard.html', username=username, transactions=transactions, income=income, expenses=expenses)
# todo: add editing/removing transactions and dates and stuff
@app.route('/add', methods=['POST'])
def add():
    if 'user' not in session:
        return redirect('/login')

    try:
        amount = float(request.form['amount'])
    except:
        amount = 0
    t_type = request.form['type']
    category = request.form['category']
    date_str = request.form['date']
    try:
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except:
        date = datetime.today().date()

    db.transactions.insert_one({
        "username": session['user'],
        "amount": amount,
        "type": t_type,
        "category": category,
        "date": str(date)
    })
    return redirect('/dashboard')

if __name__ == "__main__":
    app.run(debug=True)
