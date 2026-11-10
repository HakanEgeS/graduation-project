import ldap
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def find_user():
    uid = request.args.get("uid", "")
    conn = ldap.initialize("ldap://directory.local")
    query = "(uid=" + uid + ")"
    return str(conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, query))
