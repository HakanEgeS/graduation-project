# Label review packet

For each case below, decide independently whether the code contains a security vulnerability. If yes, give the most specific CWE you can and the line number of the vulnerable statement (the sink). Fill one row per case in label_review_form.csv. Please do not look at the project repository, the labels or the tool results while reviewing. Case numbers are random and file names are hidden on purpose.

## R01

```python
  1  import ldap
  2  from flask import Flask, request
  3  
  4  app = Flask(__name__)
  5  
  6  
  7  @app.route("/user")
  8  def find_user():
  9      uid = request.args.get("uid", "")
 10      conn = ldap.initialize("ldap://directory.local")
 11      query = "(uid=" + uid + ")"
 12      return str(conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, query))
```

## R02

```python
  1  from flask import Flask, redirect, url_for
  2  
  3  app = Flask(__name__)
  4  
  5  
  6  @app.route("/logout")
  7  def logout():
  8      return redirect(url_for("index"))
  9  
 10  
 11  @app.route("/")
 12  def index():
 13      return "home"
```

## R03

```python
  1  def calculate(expr: str):
  2      return eval(expr)
```

## R04

```python
  1  import os
  2  from flask import Flask, request
  3  
  4  app = Flask(__name__)
  5  BASE = "/srv/reports"
  6  
  7  
  8  @app.route("/report")
  9  def report():
 10      name = request.args.get("name", "")
 11      full = os.path.join(BASE, name)
 12      with open(full) as fh:
 13          return fh.read()
```

## R05

```python
  1  import yaml
  2  
  3  
  4  def parse_config(text: str):
  5      return yaml.safe_load(text)
```

## R06

```python
  1  import random
  2  
  3  
  4  def shuffle_quiz(questions: list) -> list:
  5      order = list(questions)
  6      random.shuffle(order)
  7      return order
```

## R07

```python
  1  import tempfile
  2  
  3  
  4  def write_report(text: str) -> str:
  5      path = tempfile.mktemp(suffix=".txt")
  6      with open(path, "w") as fh:
  7          fh.write(text)
  8      return path
```

## R08

```python
  1  from lxml import etree
  2  from flask import Flask, request
  3  
  4  app = Flask(__name__)
  5  TREE = etree.parse("users.xml")
  6  
  7  
  8  @app.route("/role")
  9  def role():
 10      name = request.args.get("name", "")
 11      return str(TREE.xpath("/users/user[@name='" + name + "']/role/text()"))
```

## R09

```python
  1  import random, string
  2  def reset_token() -> str:
  3      return "".join(random.choice(string.ascii_letters) for _ in range(32))
```

## R10

```python
  1  import requests
  2  password = "SuperSecret123!"
  3  def login():
  4      return requests.post("https://example.com/login", data={"user": "admin", "password": password}, timeout=5)
```

## R11

```python
  1  import sqlite3
  2  from flask import Flask, request
  3  
  4  app = Flask(__name__)
  5  
  6  
  7  @app.route("/orders")
  8  def orders():
  9      customer = request.args.get("customer", "")
 10      sql = f"SELECT id, total FROM orders WHERE customer = '{customer}'"
 11      conn = sqlite3.connect("shop.db")
 12      return str(conn.execute(sql).fetchall())
```

## R12

```python
  1  from flask import Flask, render_template_string, request
  2  
  3  app = Flask(__name__)
  4  
  5  
  6  @app.route("/greet")
  7  def greet():
  8      name = request.args.get("name", "guest")
  9      template = "<p>Hello " + name + "</p>"
 10      return render_template_string(template)
```

## R13

```python
  1  import os
  2  
  3  
  4  def publish_key(path: str) -> None:
  5      os.chmod(path, 0o777)
```

## R14

```python
  1  import hashlib
  2  
  3  
  4  def file_checksum(path: str) -> str:
  5      with open(path, "rb") as fh:
  6          return hashlib.sha256(fh.read()).hexdigest()
```

## R15

```python
  1  import ast
  2  
  3  
  4  def parse_numbers(text: str):
  5      return ast.literal_eval(text)
```
