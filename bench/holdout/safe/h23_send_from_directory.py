from flask import Flask, request, send_from_directory

app = Flask(__name__)


@app.route("/download")
def download():
    name = request.args.get("file", "")
    return send_from_directory("/var/data", name)
