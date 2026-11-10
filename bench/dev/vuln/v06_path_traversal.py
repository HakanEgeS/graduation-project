from flask import Flask, request, send_file
app = Flask(__name__)
@app.route("/download")
def download():
    name = request.args.get("file")
    return send_file("/var/data/" + name)
