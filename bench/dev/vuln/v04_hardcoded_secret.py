import requests
password = "SuperSecret123!"
def login():
    return requests.post("https://example.com/login", data={"user": "admin", "password": password}, timeout=5)
