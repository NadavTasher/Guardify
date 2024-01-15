import os
import time
import json
import hmac
import base64
import hashlib
import binascii

# Import runtypes
from runtypes import Tuple, List, Text, typechecker

# Import token types
from guardify.token import Token
from guardify.exceptions import PermissionError, SignatureError, ExpirationError

# Length of the token signature
HASH = hashlib.sha256
LENGTH = HASH().digest_size


class Authority(object):

    def __init__(self, secret):
        # Set the secret
        self._secret = secret

        # Set the validator
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
        signature = hmac.new(self._secret, buffer, HASH).digest()

        # Encode the token and return
        return base64.b64encode(buffer + signature).decode(), object

    def validate(self, token, *permissions):
        # Make sure token is a text
        if not isinstance(token, Text):
            raise TypeError("Token is not text")

        # Make sure permissions are a list of texts
        if not isinstance(permissions, (List[Text], Tuple)):
            raise TypeError("Permissions is not a list of texts")

        # Decode token to buffer
        buffer_and_signature = base64.b64decode(token)

        # Split buffer to token string and HMAC
        buffer, signature = buffer_and_signature[:-LENGTH], buffer_and_signature[-LENGTH:]

        # Validate HMAC of buffer
        if hmac.new(self._secret, buffer, HASH).digest() != signature:
            raise SignatureError("Token signature is invalid")

        # Decode string to token object
        object = Token(*json.loads(buffer))

        # Validate the expiration dates
        if object.timestamp > time.time():
            raise ExpirationError("Token timestamp is invalid")
        if object.validity < time.time():
            raise ExpirationError("Token validity is expired")

        # Validate permissions
        for permission in permissions:
            if permission not in object.permissions:
                raise PermissionError("Token is missing the %r permission" % permission)

        # Return the created object
        return object
