import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/orders")
def orders():
    customer = request.args.get("customer", "")
    sql = f"SELECT id, total FROM orders WHERE customer = '{customer}'"
    conn = sqlite3.connect("shop.db")
    return str(conn.execute(sql).fetchall())
