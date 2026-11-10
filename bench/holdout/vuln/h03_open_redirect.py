from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/login/done")
def done():
    next_url = request.args.get("next", "/")
    return redirect(next_url)
