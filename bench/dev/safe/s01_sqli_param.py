import sqlite3
def get_user(conn: sqlite3.Connection, username: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cur.fetchone()
