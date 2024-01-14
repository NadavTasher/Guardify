import pytest

from guardify import *


def test_token():
    # Create a token with value
    token = Token("0123", "Test", {"Test1": "Test2", "Test2": 0}, 10000, 10000, ["Test"])
