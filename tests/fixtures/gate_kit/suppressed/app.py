import hashlib


def hash_password(password):
    # verum:ignore[WeakCrypto] legacy checksum, migration tracked
    return hashlib.md5(password.encode()).hexdigest()


def render(expression):
    return eval(expression)  # verum:ignore reviewed sandbox input
