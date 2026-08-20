import hashlib

API_KEY = "sk_live_1234567890abcdef"


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def render(expression):
    return repr(expression)
