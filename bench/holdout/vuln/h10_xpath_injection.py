from lxml import etree
from flask import Flask, request

app = Flask(__name__)
TREE = etree.parse("users.xml")


@app.route("/role")
def role():
    name = request.args.get("name", "")
    return str(TREE.xpath("/users/user[@name='" + name + "']/role/text()"))
