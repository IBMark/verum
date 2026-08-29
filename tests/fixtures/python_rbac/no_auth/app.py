"""A project with no auth declared anywhere - it may sit behind a gateway
that terminates auth, so nothing here may flag."""

from flask import Flask

app = Flask(__name__)


@app.route("/api/orders")
def list_orders():
    return "orders"


@app.route("/api/customers")
def list_customers():
    return "customers"
