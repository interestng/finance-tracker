# Finance Tracker

A simple web app to track your income and expenses. Built with Flask and MongoDB.

## What it does

You can add transactions (income or expenses), see your spending trends, set budgets for different categories, and get some basic insights about your finances. 

## Setup

You'll need Python installed. Then:

1. Install the dependencies:
```
pip install flask pymongo bcrypt python-dotenv
```

2. Create a `.env` file in the project root with:
```
SECRET_KEY=your-secret-key-here
MONGO_URI=mongodb://localhost:27017/
```

Replace those with your actual values. For the secret key, just use any random string. For MongoDB, if you're running it locally, that URI should work. If you're using MongoDB Atlas or something else, use that connection string instead.

3. Make sure MongoDB is running

4. Run the app:
```
python app.py
```

5. Open your browser and go to `http://localhost:5000`

## Features

- Sign up / login (passwords are hashed, so that's good)
- Add income and expenses with categories and dates
- View all your transactions
- Edit or delete transactions
- See charts of your income vs expenses
- Set budgets for different categories (like "Food" or "Rent")
- Get warnings when you're close to or over budget
- Change your password, username, or theme color in settings
- Some basic highlights/insights about your spending

## Notes

- The app uses sessions, so you stay logged in until you log out
- All data is stored in MongoDB
- Default theme is purple, but you can change it to blue, orange, red, or green in settings

## In the future
- Add stronger security, maybe enough for production

- Add more QOL features, such as presets for transactions that the user can create

