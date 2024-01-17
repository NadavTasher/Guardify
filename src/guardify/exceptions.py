class TokenError(ValueError):
    pass


class ClockError(TokenError):
    pass


class ExpirationError(TokenError):
    pass


class PermissionError(TokenError):
    pass


class SignatureError(TokenError):
    pass
