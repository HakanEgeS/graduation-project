import traceback
from flask import Flask

app = Flask(__name__)


@app.errorhandler(Exception)
def on_error(exc):
    return "<pre>" + traceback.format_exc() + "</pre>", 500
