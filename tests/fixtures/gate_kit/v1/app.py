import hashlib


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def render(expression):
    return eval(expression)
