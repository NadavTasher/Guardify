import pytest

from guardify import *


def test_token():
    # Create a token with value
    Token("0123", "Test", {"Test1": "Test2", "Test2": 0}, 10000, 10000, ["Test"])

    # Make sure raises for wrong types
    with pytest.raises(TypeError):
        Token(1, 2, {3: "Test2", "Test2": 0}, 10000, 10000, ["Test"])