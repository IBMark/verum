"""Background workers: the unsafe lines mirror real-world misses, each with
its safe counterpart nearby."""

import hashlib
import json
import pickle
import random
import secrets

import requests
import yaml


def store_password(user, password):
    # UNSAFE: MD5 as a password hash.
    user.password_hash = hashlib.md5(password.encode()).hexdigest()


def content_etag(content):
    # SAFE: md5 as a cache etag is not a security use.
    etag = hashlib.md5(content).hexdigest()
    return etag


def make_otp():
    # UNSAFE: predictable RNG minting an OTP.
    otp = str(random.randint(100000, 999999))
    return otp


def make_otp_safe():
    return secrets.token_urlsafe(8)


def sample_jobs(jobs, rate):
    # SAFE: sampling is not a security use of randomness.
    return [job for job in jobs if random.random() < rate]


def push_metrics(url, payload):
    # UNSAFE: certificate verification disabled on an HTTPS call.
    return requests.post(url, json=payload, verify=False)


def push_metrics_safe(url, payload):
    return requests.post(url, json=payload, verify="/etc/ssl/certs/ca.pem")


def restore_state(blob, stream):
    # UNSAFE: pickle on non-literal bytes and a full YAML load.
    state = pickle.loads(blob)
    doc = yaml.load(stream)
    return state, doc


def restore_state_safe(text, stream):
    state = json.loads(text)
    doc = yaml.safe_load(stream)
    return state, doc
