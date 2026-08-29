"""A project that demonstrably uses route-level auth: one guarded route,
one unguarded. The unguarded one is the labelled true positive."""

from flask import Flask
from flask_login import login_required

app = Flask(__name__)


@app.route("/admin/settings")
@login_required
def admin_settings():
    return "settings"


@app.route("/api/orders")
def list_orders():
    return "orders"
