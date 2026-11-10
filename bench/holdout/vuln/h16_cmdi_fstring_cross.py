import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/dns")
def dns():
    domain = request.args.get("domain", "")
    cmd = f"nslookup {domain}"
    return str(os.system(cmd))
