class TokenError(ValueError):
    pass


class ClockError(TokenError):
    pass


class DecodingError(TokenError):
    pass


class ExpirationError(TokenError):
    pass


class TraitError(TokenError):
    pass


class SignatureError(TokenError):
    pass


class RevocationError(TokenError):
    pass
