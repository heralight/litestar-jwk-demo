import asyncio
from dataclasses import dataclass
import os
from dotenv import dotenv_values, load_dotenv

from guardpost.jwts import JWTValidator
from litestar.openapi import OpenAPIConfig
from litestar import Litestar, get, post, put
from litestar.exceptions import NotFoundException
from litestar.contrib.jwt import Token
from litestar.connection import ASGIConnection

from auth_jwk import JWKAuth


load_dotenv(dotenv_path='.env', verbose=True, override=True)
load_dotenv(dotenv_path='.env.local', verbose=True, override=True)
@dataclass
class User:
    id: str
    name: str
    email: str


@dataclass
class TodoItem:
    title: str
    done: bool

MOCK_DB: dict[str, User] = {}

TODO_LIST: list[TodoItem] = [
    TodoItem(title="Start writing TODO list", done=True),
    TodoItem(title="???", done=False),
    TodoItem(title="Profit", done=False),
]


def get_todo_by_title(todo_name) -> TodoItem:
    for item in TODO_LIST:
        if item.title == todo_name:
            return item
    raise NotFoundException(detail=f"TODO {todo_name!r} not found")


@get("/unsecure")
async def get_list(done: bool | None = None) -> list[TodoItem]:
    if done is None:
        return TODO_LIST
    return [item for item in TODO_LIST if item.done == done]

@get("/secure")
async def get_list_secure(done: bool | None = None) -> list[TodoItem]:
    if done is None:
        return TODO_LIST
    return [item for item in TODO_LIST if item.done == done]


@post("/")
async def add_item(data: TodoItem) -> list[TodoItem]:
    TODO_LIST.append(data)
    return TODO_LIST


@put("/{item_title:str}")
async def update_item(item_title: str, data: TodoItem) -> list[TodoItem]:
    todo_item = get_todo_by_title(item_title)
    todo_item.title = data.title
    todo_item.done = data.done
    return TODO_LIST


# JWTAuth requires a retrieve handler callable that receives the JWT token model and the ASGI connection
# and returns the 'User' instance correlating to it.
#
# Notes:
# - 'User' can be any arbitrary value you decide upon.
# - The callable can be either sync or async - both will work.
async def retrieve_user_handler(token: Token, connection: "ASGIConnection[Any, Any, Any, Any]") -> User | None:
    # logic here to retrieve the user instance
    return User(id=token.sub, name="John Doe", email="")
    #return MOCK_DB.get(token.sub)

def get_env_variable(var_name):
    var_value = os.environ.get(var_name)
    if var_value is None:
        raise EnvironmentError(f"Environment variable {var_name} not found")
    return var_value

def get_env_array(var_name):
    var_value = os.environ.get(var_name)
    if var_value is None:
        raise EnvironmentError(f"Environment variable {var_name} not found")
    return var_value.split(' ')

validator = JWTValidator(
        authority=get_env_variable("OPENID_AUTHORITY"),
        valid_issuers=get_env_array("OPENID_ISSUERS"),
        valid_audiences=get_env_array("OPENID_AUDIENCES"),
)

jwks = asyncio.run(validator.get_jwks())


jwt_auth = JWKAuth[User](
    retrieve_user_handler=retrieve_user_handler,
    jwt_validator=validator,

    # we are specifying which endpoints should be excluded from authentication. In this case the login endpoint
    # and our openAPI docs.
    exclude=["/unsecure", "/schema"],
)


# We create our OpenAPIConfig as usual - the JWT security scheme will be injected into it.
openapi_config = OpenAPIConfig(
    title="My API",
    version="1.0.0",
    security=[jwt_auth.openapi_security_scheme_name],
)


# We initialize the app instance and pass the jwt_auth 'on_app_init' handler to the constructor.
# The hook handler will inject the JWT middleware and openapi configuration into the app.
app = Litestar(
    route_handlers=[get_list,get_list_secure, add_item, update_item],
    on_app_init=[jwt_auth.on_app_init],
    openapi_config=openapi_config,
)