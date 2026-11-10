from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    template = "<p>Hello " + name + "</p>"
    return render_template_string(template)
