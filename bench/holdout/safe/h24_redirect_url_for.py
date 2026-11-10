from flask import Flask, redirect, url_for

app = Flask(__name__)


@app.route("/logout")
def logout():
    return redirect(url_for("index"))


@app.route("/")
def index():
    return "home"
