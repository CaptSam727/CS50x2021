import os

from datetime import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    stocks = db.execute(
        "SELECT symbol, name, SUM(shares) as shares, price, total FROM stocks WHERE id = ? GROUP BY symbol HAVING (SUM(shares)) > 0;",
        session["user_id"],
    )
    total_cash_stocks = 0
    for stock in stocks:
        quote = lookup(stock["symbol"])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["total"] = stock["price"] * stock["shares"]
        total_cash_stocks = total_cash_stocks + stock["total"]

    total_cash = total_cash_stocks + user_cash[0]["cash"]
    return render_template(
        "index.html", stocks=stocks, user_cash=user_cash[0], total_cash=total_cash
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        name = lookup(symbol)["name"]
        price = lookup(symbol)
        shares = int(request.form.get("shares"))
        user_cash = db.execute(
            "SELECT cash FROM users WHERE id = ? ", session["user_id"]
        )[0]["cash"]

        if not symbol:
            return apology("a valid symbol must be provide", 400)
        elif price is None:
            return apology("must provide valid symbol", 400)
        
        if not shares: # ERROR - doesn't work need fixing
            return apology("must provide number of shares")
        
        shares_price = shares * price["price"]
        if user_cash < (shares_price):
            return apology("cash is not sufficient", 400)
        else:
            db.execute(
                "UPDATE users SET cash = cash - ? WHERE id = ?",
                shares_price,
                session["user_id"],
            )
            db.execute(
                "INSERT INTO stocks (id, symbol, name, shares, price, total, operation, time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                session["user_id"],
                symbol.upper(),
                name,
                shares,
                price["price"],
                shares_price,
                "buy",
                datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            )
            
            flash("Transaction successful")
            return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    stocks = db.execute("SELECT * FROM stocks WHERE id = ?", session["user_id"])
    return render_template("history.html", stocks=stocks)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))
        if quote is None:
            return apology("Must provide valid symbol")
        else:
            return render_template("quoted.html", name=quote["name"], symbol=quote["symbol"], price=quote["price"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    
    # submitting the form
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 401)
        username=request.form.get("username")
        
        if not request.form.get("password"):
            return apology("must provide password", 401)
        password=request.form.get("password")
        
        if not request.form.get("password2"):
           return apology("must confirm password", 401)
        password2=request.form.get("password2")
        
        if password!=password2:
            return apology("password doesn't match", 400)
        
        rows = db.execute("SELECT * FROM users WHERE username=?", username)
        if len(rows)>0:
            return apology("Username already exists")
        
        pas = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?) ", username, pas,)
        flash("You are registered!")
        return redirect("/")
    # visiting the page
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        if not symbol:
            return apology("missing symbol")
        
        stocks = db.execute(
            "SELECT SUM(shares) as shares FROM stocks WHERE id = ? AND symbol = ?;",
            session["user_id"],
            symbol,
        )[0]
        
        if shares > stocks["shares"]:
            return apology("You don't have this number of shares")
        price = lookup(symbol)["price"]
        shares_value = price * shares
        name = lookup(symbol)["name"]
        
        db.execute(
            "INSERT INTO stocks (id, symbol, name, shares, price, total, operation, time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            session["user_id"],
            symbol.upper(),
            name,
            -shares,
            price,
            shares_value,
            "sell",
            datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        )
        
        db.execute(
            "UPDATE users SET cash = cash + ? WHERE id = ?",
            shares_value,
            session["user_id"]
        )
        flash("Transaction successful!")
        return redirect("/")
        
    else:
        stocks = db.execute(
            "SELECT symbol FROM stocks WHERE id = ? GROUP BY symbol",
            session["user_id"],
        )
        return render_template("sell.html", stocks=stocks)


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    
    if request.method == "POST":
        old_pas = request.form.get("password")
        new_pas = request.form.get("new_password")
        confirm_pas = request.form.get("confirm_password")
        
        if not old_pas:
            return apology("Missing field: Old Password")
        if not new_pas:
            return apology("Missing field: New Password")
        if not confirm_pas:
            return apology("Missing field: Confirm Password")
        
        row = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        password = row[0]["hash"]
        if not check_password_hash(password, old_pas):
            return apology("Wrong Password")
        elif new_pas == old_pas:
            return apology("New password cannot be the same as the old one")
        elif new_pas != confirm_pas:
            return apology("Passwords don't match")
        else:
            set_pas = generate_password_hash(new_pas, method="pbkdf2:sha256", salt_length=8)
            db.execute("UPDATE users SET hash = ? WHERE id = ?", set_pas, session["user_id"])
            flash("Password changed successfully")
            return redirect("/")
    
    else:
        return render_template("password.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
