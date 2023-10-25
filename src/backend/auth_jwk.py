from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Callable, Generic, Iterable, Sequence, cast

from guardpost.jwts import JWTValidator
from litestar.contrib.jwt import Token
from litestar.contrib.jwt.jwt_auth import UserType
from litestar.di import Provide
from litestar.middleware import DefineMiddleware
from litestar.openapi.spec import SecurityRequirement, Components, SecurityScheme, OAuthFlows, OAuthFlow
from litestar.security import AbstractSecurityConfig
from litestar.types import ControllerRouterHandler, Guard, SyncOrAsyncUnion, TypeEncodersMap

__all__ = ("JWKAuthenticationMiddleware")

from auth_middleware import JWKAuthenticationMiddleware

if TYPE_CHECKING:
    from typing import Any

    from litestar.connection import ASGIConnection
    from litestar.types import Method, Scopes
    from litestar.utils import dataclass


@dataclass
class JWKAuth(Generic[UserType], AbstractSecurityConfig[UserType, Token]):
    """JWT Authentication Configuration.

    This class is the main entry point to the library, and it includes methods to create the middleware, provide login
    functionality, and create OpenAPI documentation.
    """

    jwt_validator: JWTValidator
    """A JWTValidator instance."""

    retrieve_user_handler: Callable[[Any, ASGIConnection], SyncOrAsyncUnion[Any | None]]
    """Callable that receives the ``auth`` value from the authentication middleware and returns a ``user`` value.

    Notes:
        - User and Auth can be any arbitrary values specified by the security backend.
        - The User and Auth values will be set by the middleware as ``scope["user"]`` and ``scope["auth"]`` respectively.
          Once provided, they can access via the ``connection.user`` and ``connection.auth`` properties.
        - The callable can be sync or async. If it is sync, it will be wrapped to support async.

    """
    guards: Iterable[Guard] | None = field(default=None)
    """An iterable of guards to call for requests, providing authorization functionalities."""
    exclude: str | list[str] | None = field(default=None)
    """A pattern or list of patterns to skip in the authentication middleware."""
    exclude_opt_key: str = field(default="exclude_from_auth")
    """An identifier to use on routes to disable authentication and authorization checks for a particular route."""
    exclude_http_methods: Sequence[Method] | None = field(
        default_factory=lambda: cast("Sequence[Method]", ["OPTIONS", "HEAD"])
    )
    """A sequence of http methods that do not require authentication. Defaults to ['OPTIONS', 'HEAD']"""
    scopes: Scopes | None = field(default=None)
    """ASGI scopes processed by the authentication middleware, if ``None``, both ``http`` and ``websocket`` will be
    processed."""
    route_handlers: Iterable[ControllerRouterHandler] | None = field(default=None)
    """An optional iterable of route handlers to register."""
    dependencies: dict[str, Provide] | None = field(default=None)
    """An optional dictionary of dependency providers."""

    type_encoders: TypeEncodersMap | None = field(default=None)
    """A mapping of types to callables that transform them into types supported for serialization."""

    auth_header: str = field(default="Authorization")
    """Request header key from which to retrieve the token.

    E.g. ``Authorization`` or ``X-Api-Key``.
    """
    default_token_expiration: timedelta = field(default_factory=lambda: timedelta(days=1))
    """The default value for token expiration."""
    openapi_security_scheme_name: str = field(default="BearerToken")
    """The value to use for the OpenAPI security scheme and security requirements."""
    description: str = field(default="JWT api-key authentication and authorization.")
    """Description for the OpenAPI security scheme."""
    authentication_middleware_class: type[JWKAuthenticationMiddleware] = field(default=JWKAuthenticationMiddleware)
    """The authentication middleware class to use.

    Must inherit from :class:`JWKAuthenticationMiddleware`
    """

    @property
    def openapi_components(self) -> Components:
        """Create OpenAPI documentation for the JWT auth schema used.

        Returns:
            An :class:`Components <litestar.openapi.spec.components.Components>` instance.
        """
        return Components(
            security_schemes={
                self.openapi_security_scheme_name: SecurityScheme(
                    type="http",
                    scheme="Bearer",
                    name=self.auth_header,
                    bearer_format="JWT",
                    description=self.description,
                ),
                self.openapi_security_scheme_name: SecurityScheme(
                    type="oauth2",
                    scheme="Bearer",
                    name=self.auth_header,
                    security_scheme_in="header",
                    flows=OAuthFlows(implicit=OAuthFlow( # To fix and to access trough variables
                        authorization_url="https://TOFIXyouropenidproviderurl/oauth/v2/authorize",
                        token_url="https://youropenidproviderurl/oauth/v2/token",
                        scopes={"openid": "OpenId"},

                    )),  # pyright: ignore[reportGeneralTypeIssues]
                    bearer_format="JWT",
                    description=self.description,
                    # open_id_connect_url=self.jwt_validator
                )
            }
        )

    @property
    def security_requirement(self) -> SecurityRequirement:
        """Return OpenAPI 3.1.

        :data:`SecurityRequirement <.openapi.spec.SecurityRequirement>`

        Returns:
            An OpenAPI 3.1
            :data:`SecurityRequirement <.openapi.spec.SecurityRequirement>`
            dictionary.
        """
        return {self.openapi_security_scheme_name: []}

    @property
    def middleware(self) -> DefineMiddleware:
        """Create :class:`JWTAuthenticationMiddleware` wrapped in
        :class:`DefineMiddleware <.middleware.base.DefineMiddleware>`.

        Returns:
            An instance of :class:`DefineMiddleware <.middleware.base.DefineMiddleware>`.
        """
        return DefineMiddleware(
            self.authentication_middleware_class,
            auth_header=self.auth_header,
            exclude=self.exclude,
            exclude_opt_key=self.exclude_opt_key,
            exclude_http_methods=self.exclude_http_methods,
            retrieve_user_handler=self.retrieve_user_handler,
            scopes=self.scopes,
            jwt_validator=self.jwt_validator,
        )
