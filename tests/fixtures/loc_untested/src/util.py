# A Python module, for the hash-comment family.
import sys


def widen(value):
    """A docstring.

    Counted as code, deliberately.
    """
    return value * 2  # trailing comment, so this line is code
