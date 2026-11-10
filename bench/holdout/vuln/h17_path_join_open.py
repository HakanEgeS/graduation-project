import os
from flask import Flask, request

app = Flask(__name__)
BASE = "/srv/reports"


@app.route("/report")
def report():
    name = request.args.get("name", "")
    full = os.path.join(BASE, name)
    with open(full) as fh:
        return fh.read()
