from flask import Flask, render_template, request, redirect, session, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
from dotenv import load_dotenv
import os
import bcrypt
import re

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
client = MongoClient(os.getenv("MONGO_URI"))
db = client.finance_db

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not password:
            flash('Please fill in all fields', 'error')
            return render_template('signup.html')
        
        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return render_template('signup.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('signup.html')
        
        if db.users.find_one({"username": username}):
            flash('Username already exists', 'error')
            return render_template('signup.html')
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        db.users.insert_one({
            "username": username, 
            "password": hashed_password.decode('utf-8')
        })
        flash('Account created successfully! Please login.', 'success')
        return redirect('/login')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please fill in all fields', 'error')
            return render_template('login.html')
        
        user = db.users.find_one({"username": username})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user'] = user['username']
            flash('Login successful!', 'success')
            return redirect('/dashboard')
        
        flash('Invalid username or password', 'error')
        return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    username = session['user']
    transactions = list(db.transactions.find({"username": username}))
    for t in transactions:
        t['_id'] = str(t['_id'])
    income = sum(t['amount'] for t in transactions if t['type'] == 'income')
    expenses = sum(t['amount'] for t in transactions if t['type'] == 'expense')
    
    highlights = []
    today = datetime.today()
    last_month = today.replace(month=today.month-1 if today.month>1 else 12)
    last_month_expenses = sum(t['amount'] for t in transactions if t['type']=='expense' and datetime.strptime(t['date'],'%Y-%m-%d').month == last_month.month)
    current_month_expenses = sum(t['amount'] for t in transactions if t['type']=='expense' and datetime.strptime(t['date'],'%Y-%m-%d').month == today.month)
    if last_month_expenses > 0:
        change = ((current_month_expenses - last_month_expenses)/last_month_expenses)*100
        if change > 0:
            highlights.append(f"Your expenses increased by {change:.0f}% compared to last month!")
        elif change < 0:
            highlights.append(f"Your expenses decreased by {abs(change):.0f}% compared to last month!")

    most_common_category = "N/A"
    if transactions:
        categories = [t['category'] for t in transactions]
        most_common_category = max(set(categories), key=categories.count)

    return render_template('dashboard.html', username=username, transactions=transactions, income=income, expenses=expenses, highlights=highlights, most_common_category=most_common_category)

@app.route('/add', methods=['POST'])
def add():
    if 'user' not in session:
        return redirect('/login')
    try:
        amount = float(request.form.get('amount',0))
    except:
        amount = 0
    t_type = request.form.get('type','expense')
    category = request.form.get('category','Misc')
    date_str = request.form.get('date')
    try:
        date = datetime.strptime(date_str,'%Y-%m-%d').date()
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

@app.route('/delete/<id>', methods=['POST'])
def delete(id):
    if 'user' not in session:
        return redirect('/login')
    db.transactions.delete_one({"_id": ObjectId(id), "username": session['user']})
    return redirect('/dashboard')

@app.route('/edit/<id>', methods=['POST'])
def edit(id):
    if 'user' not in session:
        return redirect('/login')
    transaction = db.transactions.find_one({"_id": ObjectId(id), "username": session['user']})
    if transaction:
        try:
            amount = float(request.form.get('amount', transaction['amount']))
        except:
            amount = transaction['amount']
        t_type = request.form.get('type', transaction['type'])
        category = request.form.get('category', transaction['category'])
        date = request.form.get('date', transaction['date'])
        db.transactions.update_one({"_id": ObjectId(id)}, {"$set": {"amount": amount, "type": t_type, "category": category, "date": date}})
    return redirect('/dashboard')

if __name__ == "__main__":
    app.run(debug=True)
