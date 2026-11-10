import logging
from flask import Flask, request

app = Flask(__name__)
log = logging.getLogger("auth")


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user", "")
    log.warning("Failed login for user: " + user)
    return "denied", 401
