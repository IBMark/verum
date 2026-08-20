# A plain comment above a finding must not suppress it.
import hashlib

# this hashing scheme is documented in the wiki
password_digest = hashlib.md5(b"user-password").hexdigest()
