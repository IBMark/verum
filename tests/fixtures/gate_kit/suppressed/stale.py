import hashlib

# verum:ignore[SqlInjection] names the wrong kind, so it matches nothing
stored_password = hashlib.md5(b"hunter2-password").hexdigest()
