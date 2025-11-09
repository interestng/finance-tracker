from flask import Flask, render_template, request, redirect, session, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
from dotenv import load_dotenv
from urllib.parse import unquote
import os
import bcrypt

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

    user = db.users.find_one({"username": username})
    
    category_budgets = user.get('category_budgets', {}) if user else {}
    budget = sum(category_budgets.values()) if category_budgets else 0
    
    budget_percentage = 0
    if budget > 0:
        budget_percentage = (current_month_expenses / budget) * 100

    category_spending = {}
    for category, budget_amount in category_budgets.items():
        category_expenses = sum(t['amount'] for t in transactions if t['type'] == 'expense' and t['category'] == category and datetime.strptime(t['date'],'%Y-%m-%d').month == today.month)
        category_spending[category] = {
            'spent': category_expenses,
            'budget': budget_amount,
            'percentage': (category_expenses / budget_amount * 100) if budget_amount > 0 else 0
        }

    theme = user.get('theme', 'purple') if user else 'purple'

    return render_template('dashboard.html', username=username, transactions=transactions, income=income, expenses=expenses, highlights=highlights, most_common_category=most_common_category, budget=budget, current_month_expenses=current_month_expenses, budget_percentage=budget_percentage, theme=theme, category_budgets=category_budgets, category_spending=category_spending)

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

@app.route('/set_category_budget', methods=['POST'])
def set_category_budget():
    if 'user' not in session:
        return redirect('/login')
    username = session['user']
    category = request.form.get('category', '').strip()
    try:
        budget_amount = float(request.form.get('budget_amount', 0))
    except:
        budget_amount = 0
    
    if category and budget_amount > 0:
        user = db.users.find_one({"username": username})
        category_budgets = user.get('category_budgets', {}) if user else {}
        category_budgets[category] = budget_amount
        db.users.update_one({"username": username}, {"$set": {"category_budgets": category_budgets}})
    
    return redirect('/dashboard#budget')

@app.route('/delete_category_budget/<path:category>', methods=['POST'])
def delete_category_budget(category):
    if 'user' not in session:
        return redirect('/login')
    username = session['user']
    category = unquote(category)
    user = db.users.find_one({"username": username})
    if user:
        category_budgets = user.get('category_budgets', {})
        if category in category_budgets:
            del category_budgets[category]
            db.users.update_one({"username": username}, {"$set": {"category_budgets": category_budgets}})
    return redirect('/dashboard#budget')

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user' not in session:
        return redirect('/login')
    username = session['user']
    user = db.users.find_one({"username": username})
    theme = user.get('theme', 'purple') if user else 'purple'
    
    # Clear any lingering flash messages when accessing settings via GET
    if request.method == 'GET':
        session.pop('_flashes', None)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'change_password':
            old_password = request.form.get('old_password', '')
            new_password = request.form.get('new_password', '')
            
            if not old_password or not new_password:
                flash('Please fill in all password fields', 'error')
                return render_template('settings.html', username=username, theme=theme)
            
            if len(new_password) < 6:
                flash('New password must be at least 6 characters long', 'error')
                return render_template('settings.html', username=username, theme=theme)
            
            if user and bcrypt.checkpw(old_password.encode('utf-8'), user['password'].encode('utf-8')):
                hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                db.users.update_one({"username": username}, {"$set": {"password": hashed_password.decode('utf-8')}})
                flash('Password changed successfully!', 'success')
            else:
                flash('Old password is incorrect', 'error')
                return render_template('settings.html', username=username, theme=theme)
        
        elif action == 'change_username':
            new_username = request.form.get('new_username', '').strip()
            
            if not new_username:
                flash('Please enter a new username', 'error')
                return render_template('settings.html', username=username, theme=theme)
            
            if len(new_username) < 3:
                flash('Username must be at least 3 characters long', 'error')
                return render_template('settings.html', username=username, theme=theme)
            
            if db.users.find_one({"username": new_username}):
                flash('Username already exists', 'error')
                return render_template('settings.html', username=username, theme=theme)
            
            db.users.update_one({"username": username}, {"$set": {"username": new_username}})
            db.transactions.update_many({"username": username}, {"$set": {"username": new_username}})
            session['user'] = new_username
            flash('Username changed successfully!', 'success')
            username = new_username
        
        elif action == 'change_theme':
            new_theme = request.form.get('theme', 'purple')
            db.users.update_one({"username": username}, {"$set": {"theme": new_theme}})
            flash('Theme updated successfully!', 'success')
            theme = new_theme
    
    return render_template('settings.html', username=username, theme=theme)


if __name__ == "__main__":
    app.run(debug=True)
