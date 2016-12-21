"""Exceptions for the GoPhish API"""

class NoAuthenticationProvided(Exception):
    """No authentication was provided when instantiating the module."""
class InvalidToken(Exception):
    """Token is not valid."""
class InvalidLoggingType(Exception):
    """Requesting logs for events that don't exist"""

class SQLError(Exception):
    """Generic SQL Error"""
    class SQLDBNonExist(Exception):
        """SQL DB Not Found"""

class GoPhish(Exception):
    """Generic GoPhish Error"""
    class NoHostProvided(Exception):
        """No host or IP provided"""
    class NoPortProvided(Exception):
        """No port provided"""
    class NoAPIKeyProvided(Exception):
        """No API Key provided"""

class HTTPError(Exception):
    """Generic HTTP Error"""
    class BadRequest(Exception):
        """The request is not valid; HTTP 400"""
    class UnAuthorized(Exception):
        """Unauthorized; HTTP 401"""
    class MethodNotAllowed(Exception):
        """Wrong HTTP method used; HTTP 405"""
    class UnKnownHTTPError(Exception):
        """HTTP Error catch all"""
    class GroupNameInUse(Exception):
        """Group name is used"""