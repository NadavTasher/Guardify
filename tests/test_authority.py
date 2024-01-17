import os
import time
import pytest
import base64
import contextlib

from guardify import *


@pytest.fixture()
def authority(request):
    return Authority(os.urandom(10))


@contextlib.contextmanager
def patch_time(new_time):
    # Store original time
    original_time = time.time

    try:
        # Patch the function
        time.time = new_time

        # Yield for execution
        yield
    finally:
        # Restore original time
        time.time = original_time


def test_issue(authority):
    # Issue a token
    string, token = authority.issue("Hello World", {"Hello": "World"}, ["Hello"])

    # Make sure string is a string
    assert isinstance(string, (str, u"".__class__))

    # Make sure token is a token
    assert isinstance(token, Token)


def test_validate(authority):
    # Issue a token
    string, token = authority.issue("Hello World", {"Hello": "World"}, ["Hello"])

    # Validate the token
    parsed_token = authority.validate(string)

    # Make sure parsed token and generated token match
    assert parsed_token == token

    # Make sure we can't validate random stuff
    with pytest.raises(TypeError):
        authority.validate(10)


def test_permissions(authority):
    # Issue a token
    string, _ = authority.issue("Hello World", {"Hello": "World"}, ["Hello"])

    # Make sure the validation does not raise
    authority.validate(string)
    authority.validate(string, "Hello")

    # Make sure the validation raises
    with pytest.raises(PermissionError):
        authority.validate(string, "World")


def test_expiration(authority):
    # Issue a token
    string, _ = authority.issue("Hello World", {"Hello": "World"}, ["Hello"], 100)

    # Make sure the validation does not raise
    authority.validate(string)

    # Patch time to return 0 - we are in the past
    with patch_time(lambda: 0):
        with pytest.raises(ClockError):
            authority.validate(string)

    # Make sure the validation does not raise
    authority.validate(string)

    # Create new time
    future_time = time.time() + 1000

    # Patch time to return 0 - we are in the past
    with patch_time(lambda: future_time):
        with pytest.raises(ExpirationError):
            authority.validate(string)


def test_signature(authority):
    # Issue a token
    string, _ = authority.issue("Hello World", {"Hello": "World"}, ["Hello"])

    # Patch the string
    buffer = base64.b64decode(string)
    buffer = buffer[:-1]
    string = base64.b64encode(buffer).decode()

    # Make sure validation raises a signature error
    with pytest.raises(SignatureError):
        authority.validate(string)


def test_tokentype(authority):
    # Issue a token
    string, _ = authority.issue("Hello World", {"Hello": "World"}, ["Hello"])

    # Make sure the type checker works
    assert authority.TokenType(string).contents["Hello"] == "World"

    # Make sure the type checker works with permissions
    assert authority.TokenType["Hello"](string).contents["Hello"] == "World"

    # Make sure the type checker works with wrong permissions
    with pytest.raises(PermissionError):
        authority.TokenType["World"](string).contents["Hello"] == "World"

    # Check the type checker using isinstance
    assert isinstance(string, authority.TokenType)
    assert not isinstance("Hello World", authority.TokenType)
