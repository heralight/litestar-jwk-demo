# Python Litestar and OIDC providers

This is POC to demonstrate the integration with OIDC providers like Zitadel, Keycloak, Oauth, ...etc.

## Deps

- PDM

```sh
pdm venv create
. .venv/bin/activate
pdm install
```

## Configuration

Set your settings inside .env file.

## Run

```sh
litestar run -d
``````

## How

In Litestar, auth_jwk is an implementation of [AbstractSecurityConfig](https://docs.litestar.dev/2/usage/security/security-backends.html#abstractsecurityconfig) that use https://github.com/Neoteroi/GuardPost to get jwk from OIDC providers, manage cache, and validate jwt.

You can test it with the zitadel-app project and a [zitadel instance](https://zitadel.com/).

 **remember to change the client access_token to JWT**.
