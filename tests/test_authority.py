import os
import pytest
import shutil
import tempfile

from guardify import *


def test_issue():
    # Create a token authority with random key
    authority = Authority(os.urandom(10))

    # Issue a token
    string, token = authority.issue("Hello World", {"Hello": "World"}, ["Hello"])

    # Make sure string is a string
    assert isinstance(string, str)

    # Make sure token is a token
    assert isinstance(token, Token)
