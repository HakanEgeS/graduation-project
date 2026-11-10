import os, requests
def login():
    return requests.post("https://example.com/login", data={"user": "admin", "password": os.environ["APP_PASSWORD"]}, timeout=5)
