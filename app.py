# This web application was inspired by Roblox, brick-hill, and most importantly, CS50 Finance
# Additionally, thanks to GitHub Copilot for assisting me through this project

# Define modules to use in the program
import bcrypt
import calendar
from datetime import date, datetime
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from functools import wraps
from string import ascii_letters, digits, punctuation
import sqlite3

# Create an application using flask
app = Flask(__name__)
app.secretkey = "somesecretkey"

# Configure session and run it
app.config.update(
    SESSION_PERMANENT=False,
    SESSION_TYPE="filesystem"
)
Session(app)

c = sqlite3.connect("site.db", check_same_thread=False)
db = c.cursor()

# Credits to CS50 for this after request to make sure clients have an up-to-date website
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Credits to CS50 for this wrapper function!
def login_required(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return function(*args, **kwargs)

    return decorated_function


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", message="Page does not exist")


@app.route("/currency", methods=['GET', 'POST'])
@login_required
def currency():

    # Value of currencies related to one another
    cpt = 0.1
    tpc = 10

    if request.method == 'POST':

        if "cash-button" in request.form:
            cash = request.form.get("cash")

            if not cash:
                flash("Error 400 | No amount provided", "danger")
                return redirect("/currency")

            if not cash.isdigit():
                flash("Error 400 | Invalid input", "danger")
                return redirect("/currency")
            else:
                cash = int(cash)

            info = db.execute("SELECT cash, tickets FROM users WHERE id = ?", (session["user_id"],)).fetchall()
            user_cash = info[0][0]
            user_tickets = info[0][1]

            if not cash > 0:
                flash("Error 400 | Please provide an amount greater than 0", "danger")
                return redirect("/currency")
            elif cash > user_cash:
                flash(f"Error 400 | You need {cash - user_cash} more cash to convert this!", "danger")
                return redirect("/currency")

            db.execute("UPDATE users SET cash = ?, tickets = ? WHERE id = ?", (user_cash - cash, user_tickets + (cash * tpc), session["user_id"]))
            c.commit()

        elif "ticket-button" in request.form:
            tickets = request.form.get("tickets")

            if not tickets:
                flash("Error 400 | No amount provided", "danger")
                return redirect("/currency")

            if not tickets.isdigit():
                flash("Error 400 | Invalid input", "danger")
                return redirect("/currency")
            else:
                tickets = int(tickets)

            info = db.execute("SELECT cash, tickets FROM users WHERE id = ?", (session["user_id"],)).fetchall()
            user_cash = info[0][0]
            user_tickets = info[0][1]
            left_over = tickets % tpc

            if not tickets > 0:
                flash("Error 400 | Please provide an amount greater than 0", "danger")
                return redirect("/currency")
            elif tickets > user_tickets:
                flash(f"Error 400 | You need {tickets - user_tickets} more tickets to convert this!", "danger")
                return redirect("/currency")

            db.execute("UPDATE users SET cash = ?, tickets = ? WHERE id = ?", (user_cash + (tickets - left_over) * cpt, user_tickets - tickets + left_over, session["user_id"]))
            c.commit()

        flash("Success!", "success")
        return redirect("/")
    else:
        info = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchall()
        user = info[0][1]
        cash = info[0][6]
        tickets = info[0][7]

        return render_template("currency.html", username=user, cash=cash, tickets=tickets)

@app.route("/")
@login_required
def index():
    # Homepage for user

    info = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchall()
    user = info[0][1]
    cash = info[0][6]
    tickets = info[0][7]

    return render_template("index.html", username=user, cash=cash, tickets=tickets)


@app.route("/login", methods=['GET', 'POST'])
def login():

    if session.get("user_id"):
        return redirect("/")

    if request.method == 'POST':

        username = request.form.get("username")
        password = request.form.get("password")

        # Error checking
        if not username:
            flash("Error 400 | No username provided", "danger")
            return redirect("/login")
        elif not password:
            flash("Error 400 | No password provided", "danger")
            return redirect("/login")

        db.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,))
        row = db.fetchall()
        if len(row) != 1 or (not bcrypt.checkpw(password.encode('utf-8'), row[0][3])):
            flash("Error 403 | Incorrect username and/or password", "danger")
            return redirect("/login")

        session["user_id"] = row[0][0]

        flash("Successfully logged in!", "success")
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/profile/<user_id>")
def profile(user_id):

    if user_id.isdigit():
        db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = db.fetchall()

        if not row:
            return render_template("error.html", message="User does not exist")
        d = row[0][4]
        formatted_date = d[5:7] + "/" + d[8:10] + "/" + d[0:4]
        return render_template("profile.html", username=row[0][1], user_id=row[0][0], join_date=formatted_date, cash=row[0][6], tickets=row[0][7])
    else:
        return render_template("error.html", message="Invalid request")

@app.route("/register", methods=['GET', 'POST'])
def register():

    if session.get("user_id"):
        return redirect("/")

    if request.method == 'POST':

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        email = request.form.get("email")
        month = request.form.get("month")
        day = request.form.get("day")
        year = request.form.get("year")

        # Error checking
        if not username:
            flash("Error 400 | No username provided", "danger")
            return redirect("/register")
        elif not password or not confirmation:
            flash("Error 400 | No password/confirmation provided", "danger")
            return redirect("/register")
        elif not email:
            flash("Error 400 | No email provided", "danger")
            return redirect("/register")
        elif not month or not day or not year:
            flash("Error 400 | No birthday provided", "danger")
            return redirect("/register")
        elif not all(letter in ascii_letters for letter in username[0] + username[-1]):
            flash("Error 400 | Username cannot start/end with numbers, punctuation, or symbols", "danger")
            return redirect("/register")
        elif len(username) < 3 or len(username) > 20:
            flash("Error 400 | Username should be between 3-20 characters long", "danger")
            return redirect("/register")
        elif len(password) < 8 or len(password) > 20:
            flash("Error 400 | Password should be between 8-20 characters long", "danger")
            return redirect("/register")
        elif password != confirmation:
            flash("Error 400 | Passwords do not match", "danger")
            return redirect("/register")
        elif "@" not in email:
            flash("Error 400 | Invalid email", "danger")
            return redirect("/register")

        # Make sure username is valid
        for char in username:
            if char not in ascii_letters and char not in digits and char not in "_":
                flash("Error 400 | Invalid username", "danger")
                return redirect("/register")

        # Make sure the birthdate is valid
        try:
            datetime(int(year), int(month), int(day))
        except ValueError:
            flash("Error 400 | Invalid birthday", "danger")
            return redirect("/register")

        db.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,))
        row = db.fetchall()
        if len(row) != 1:
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            formatted_birthday = f"{month}/{day}/{year}"
            db.execute("INSERT INTO users (username, email, pw_hash, birthday) VALUES(?, ?, ?, ?)", (username, email, hashed_pw, formatted_birthday))
            c.commit()
            db.execute("SELECT id FROM users WHERE username = ?", (username,))
            id = db.fetchall()[0][0]
            session["user_id"] = id
        else:
            flash("Error 400 | Username already taken", "danger")
            return redirect("/register")

        flash("Successfully registed!", "success")
        return redirect("/")
    else:
        return render_template("register.html", months=list(calendar.month_name)[1:], days=range(1, 32), years=range(2024, 1909, -1))


@app.route("/settings", methods=['GET', 'POST'])
@login_required
def settings():

    if request.method == 'POST':
        password = request.form.get("password")
        newpass = request.form.get("newpass")

        if not password or not newpass:
            flash("Error 400 | No password(s) provided", "danger")
            return redirect("/settings")
        elif password == newpass:
            flash("Error 400 | New password should not be the same as the current one", "danger")
            return redirect("/settings")
        elif len(newpass) < 8 or len(newpass) > 20:
            flash("Error 400 | Password should be between 8-20 characters long", "danger")
            return redirect("/settings")

        row = db.execute("SELECT pw_hash FROM users WHERE id = ?", (session["user_id"],)).fetchall()
        pw_hash = row[0][0]
        if not bcrypt.checkpw(password.encode('utf-8'), pw_hash):
            flash("Error 403 | Incorrect password", "danger")
            return redirect("/settings")

        hashed_pw = bcrypt.hashpw(newpass.encode('utf-8'), bcrypt.gensalt())
        db.execute("UPDATE users SET pw_hash = ? WHERE id = ?", (hashed_pw, session["user_id"]))
        c.commit()

        flash("Successfully changed password!", "success")
        return redirect("/")
    else:
        info = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchall()
        user = info[0][1]
        cash = info[0][6]
        tickets = info[0][7]

    return render_template("settings.html", username=user, cash=cash, tickets=tickets)
