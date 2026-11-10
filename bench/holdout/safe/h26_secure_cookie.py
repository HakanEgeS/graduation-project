from flask import Flask, make_response

app = Flask(__name__)


@app.route("/session")
def session_start():
    resp = make_response("ok")
    resp.set_cookie("sid", "abc123", secure=True, httponly=True, samesite="Lax")
    return resp
