"""Tag helpers - the shared-mutable-default trap next to the None idiom."""


def add_tag(tag, tags=[]):
    tags.append(tag)
    return tags


def merge_options(overrides={}):
    return {"retries": 3, **overrides}


def seen_ids(initial=set()):
    return initial


def add_tag_fresh(tag, tags=None):
    if tags is None:
        tags = []
    tags.append(tag)
    return tags


def merge_options_fresh(overrides=None):
    overrides = overrides or {}
    return {"retries": 3, **overrides}


def with_scalars(count=0, name="order", flags=()):
    return count, name, flags
