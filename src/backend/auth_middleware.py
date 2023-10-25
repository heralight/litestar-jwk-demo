from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Sequence

from guardpost.jwts import JWTValidator, InvalidAccessToken
from jose import JWTError
from jwt import DecodeError
from litestar.contrib.jwt.jwt_token import Token
from litestar.exceptions import NotAuthorizedException, ImproperlyConfiguredException
from litestar.middleware import AbstractAuthenticationMiddleware, AuthenticationResult

__all__ = ("JWKAuthenticationMiddleware")

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.types import ASGIApp, Method, Scopes
    from litestar.utils import AsyncCallable


class JWKAuthenticationMiddleware(AbstractAuthenticationMiddleware):
    """JWK Authentication middleware.

    This class provides JWK authentication functionalities.
    """

    __slots__ = (
        "auth_header",
        "retrieve_user_handler",
        "jwt_validator",
    )

    def __init__(
            self,
            app: ASGIApp,
            auth_header: str,
            exclude: str | list[str] | None,
            exclude_http_methods: Sequence[Method] | None,
            exclude_opt_key: str,
            retrieve_user_handler: AsyncCallable[[Token, ASGIConnection[Any, Any, Any, Any]], Any],
            scopes: Scopes,
            jwt_validator: JWTValidator,
    ) -> None:
        """Check incoming requests for an encoded token in the auth header specified, and if present retrieve the user
        from persistence using the provided function.

        Args:
            algorithm: JWT hashing algorithm to use.
            app: An ASGIApp, this value is the next ASGI handler to call in the middleware stack.
            auth_header: Request header key from which to retrieve the token. E.g. ``Authorization`` or ``X-Api-Key``.
            exclude: A pattern or list of patterns to skip.
            exclude_opt_key: An identifier to use on routes to disable authentication for a particular route.
            exclude_http_methods: A sequence of http methods that do not require authentication.
            retrieve_user_handler: A function that receives a :class:`Token <.contrib.jwt.Token>` and returns a user,
                which can be any arbitrary value.
            scopes: ASGI scopes processed by the authentication middleware.
            jwt_validator: Secret for decoding the JWT token. This value should be equivalent to the secret used to
                encode it.
        """
        super().__init__(
            app=app,
            exclude=exclude,
            exclude_from_auth_key=exclude_opt_key,
            exclude_http_methods=exclude_http_methods,
            scopes=scopes,
        )
        self.auth_header = auth_header
        self.retrieve_user_handler = retrieve_user_handler
        self.jwt_validator = jwt_validator

    async def authenticate_request(self, connection: ASGIConnection[Any, Any, Any, Any]) -> AuthenticationResult:
        """Given an HTTP Connection, parse the JWT api key stored in the header and retrieve the user correlating to the
        token from the DB.

        Args:
            connection: An Litestar HTTPConnection instance.

        Returns:
            AuthenticationResult

        Raises:
            NotAuthorizedException: If token is invalid or user is not found.
        """
        auth_header = connection.headers.get(self.auth_header)
        if not auth_header:
            raise NotAuthorizedException("No JWT token found in request header")
        encoded_token = auth_header.partition(" ")[-1]
        return await self.authenticate_token(encoded_token=encoded_token, connection=connection)

    async def decode(self, encoded_token: str) -> Token:
        """Decode a passed in token string and returns a Token instance.

        Args:
            encoded_token: A base64 string containing an encoded JWT.

        Returns:
            A decoded Token instance.

        Raises:
            NotAuthorizedException: If the token is invalid.
        """
        try:
            payload = await self.jwt_validator.validate_jwt(access_token=encoded_token)
            #payload = jwt.decode(token=encoded_token, key=secret, algorithms=[algorithm], options={"verify_aud": False})
            exp = datetime.fromtimestamp(payload.pop("exp"), tz=timezone.utc)
            iat = datetime.fromtimestamp(payload.pop("iat"), tz=timezone.utc)
            field_names = {f.name for f in dataclasses.fields(Token)}
            extra_fields = payload.keys() - field_names
            extras = payload.pop("extras", {})
            for key in extra_fields:
                extras[key] = payload.pop(key)
            return Token(exp=exp, iat=iat, **payload, extras=extras)
        except (KeyError, JWTError, ImproperlyConfiguredException, DecodeError, InvalidAccessToken) as e:
            raise NotAuthorizedException("Invalid token") from e

    async def authenticate_token(
            self, encoded_token: str, connection: ASGIConnection[Any, Any, Any, Any]
    ) -> AuthenticationResult:
        """Given an encoded JWT token, parse, validate and look up sub within token.

        Args:
            encoded_token: Encoded JWT token.
            connection: An ASGI connection instance.

        Raises:
            NotAuthorizedException: If token is invalid or user is not found.

        Returns:
            AuthenticationResult
        """
        token = await self.decode(
            encoded_token=encoded_token
        )



        user = await self.retrieve_user_handler(token, connection)

        if not user:
            raise NotAuthorizedException()

        return AuthenticationResult(user=user, auth=token)

