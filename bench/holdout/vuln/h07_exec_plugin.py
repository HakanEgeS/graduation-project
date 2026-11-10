from flask import Flask, request

app = Flask(__name__)


@app.route("/plugin", methods=["POST"])
def run_plugin():
    source = request.form["code"]
    scope = {}
    exec(source, scope)
    return str(scope.get("result"))
