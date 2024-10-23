import os
import time
import json
import hmac
import base64
import typing
import hashlib
import binascii

# Import runtypes
from runtypes import RunType

# Import token types
from guardify.token import Token
from guardify.errors import ClockError, DecodingError, ExpirationError, RoleError, SignatureError, RevocationError


class Authority(object):

    def __init__(self, secret: typing.ByteString, hash: typing.Callable[..., typing.Any] = hashlib.sha256, revocations: typing.MutableMapping[str, int] = dict()) -> None:
        # Set internal parameters
        self._hash = hash
        self._secret = secret
        self._revocations = revocations

        # Calculate the digest length
        self._length = self._hash(self._secret).digest_size

        # Set the type checker
        self.TokenType = RunType("TokenType", caster=self.validate, checker=self.validate)

    def issue(self, name: str, contents: typing.Mapping[str, typing.Any] = {}, roles: typing.Sequence[str] = [], validity: int = 60 * 60 * 24 * 365) -> typing.Tuple[str, Token]:
        # Calculate token validity
        timestamp = int(time.time())

        # Create identifier
        identifier = binascii.b2a_hex(os.urandom(6)).decode()

        # Create token object
        object = Token(identifier, name, contents, timestamp + validity, timestamp, roles)

        # Create token buffer from object
        buffer = json.dumps(object).encode()

        # Create token signature from token buffer
        signature = hmac.new(self._secret, buffer, self._hash).digest()

        # Encode the token and return
        return base64.b64encode(buffer + signature).decode(), object

    def validate(self, token: typing.Union[str, Token], *roles: str) -> Token:
        # Make sure token is a text
        if not isinstance(token, (str, Token)):
            raise TypeError(f"Token must be a string or a Token")

        # If the token is a string, parse it
        if isinstance(token, str):
            # Make sure the entire token string is not revoked
            if token in self._revocations:
                raise RevocationError(f"Token has been revoked {int(time.time() - self._revocations[token])} seconds ago")

            try:
                # Decode token to buffer
                buffer_and_signature = base64.b64decode(token)
            except binascii.Error:
                # Raise decoding error
                raise DecodingError(f"Token decoding failed")

            # Split buffer to token string and HMAC
            buffer, signature = buffer_and_signature[:-self._length], buffer_and_signature[-self._length:]

            # Validate HMAC of buffer
            if hmac.new(self._secret, buffer, self._hash).digest() != signature:
                raise SignatureError(f"Token signature is invalid")

            # Decode string to token object
            token = Token(*json.loads(buffer))

        # Make sure token isn't from the future
        if token.timestamp > time.time():
            raise ClockError(f"Token is invalid")

        # Make sure token isn't expired
        if token.validity < time.time():
            raise ExpirationError(f"Token is expired")

        # Validate roles
        for role in roles:
            if role not in token.roles:
                raise RoleError(f"Token is missing the {role!r} role")

        # Check revocations
        if token.id in self._revocations:
            raise RevocationError(f"Token has been revoked {int(time.time() - self._revocations[token.id])} seconds ago")

        # Return the created object
        return token

    def revoke(self, token: typing.Union[str, Token]) -> None:
        # Check whether the value is a token
        if isinstance(token, Token):
            # The token ID
            identifier = token.id
        elif isinstance(token, str):
            # An ID or just the entire string
            identifier = token
        else:
            # Not the right type
            raise TypeError(f"Invalid type for revocation")

        # Revoke the token!
        self._revocations[identifier] = int(time.time())
