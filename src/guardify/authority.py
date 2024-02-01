import os
import time
import json
import hmac
import base64
import hashlib
import binascii

# Import runtypes
from runtypes import Text, typechecker

# Import token types
from guardify.token import Token
from guardify.exceptions import ClockError, ExpirationError, PermissionError, SignatureError


class Authority(object):

    def __init__(self, secret, hash=hashlib.sha256):
        # Set internal parameters
        self._hash = hash
        self._secret = secret

        # Calculate the digest length
        self._length = self._hash(self._secret).digest_size

        # Set the type checker
        self.TokenType = typechecker(self.validate)

    def issue(self, name, contents={}, permissions=[], validity=60 * 60 * 24 * 365):
        # Calculate token validity
        timestamp = int(time.time())

        # Create identifier
        identifier = binascii.b2a_hex(os.urandom(6)).decode()

        # Create token object
        object = Token(identifier, name, contents, timestamp + validity, timestamp, permissions)

        # Create token buffer from object
        buffer = json.dumps(object).encode()

        # Create token signature from token buffer
        signature = hmac.new(self._secret, buffer, self._hash).digest()

        # Encode the token and return
        return base64.b64encode(buffer + signature).decode(), object

    def validate(self, token, *permissions):
        # Make sure token is a text
        if not isinstance(token, Text):
            raise TypeError("Token must be text")

        # Decode token to buffer
        buffer_and_signature = base64.b64decode(token)

        # Split buffer to token string and HMAC
        buffer, signature = buffer_and_signature[:-self._length], buffer_and_signature[-self._length:]

        # Validate HMAC of buffer
        if hmac.new(self._secret, buffer, self._hash).digest() != signature:
            raise SignatureError("Token signature is invalid")

        # Decode string to token object
        object = Token(*json.loads(buffer))

        # Make sure token isn't from the future
        if object.timestamp > time.time():
            raise ClockError("Token is invalid")

        # Make sure token isn't expired
        if object.validity < time.time():
            raise ExpirationError("Token is expired")

        # Validate permissions
        for permission in permissions:
            if permission not in object.permissions:
                raise PermissionError("Token is missing the %r permission" % permission)

        # Return the created object
        return object
