import base64
import itertools
import secrets
import typing

import quart.flask_patch  # noqa:F401
from quart import (
    current_app,
    request,
)

import flask_babel
from flask_babel import _

from . import prosodyclient


client = prosodyclient.ProsodyClient()
client.default_login_redirect = "main.login"

babel = flask_babel.Babel()


@babel.localeselector  # type:ignore
def selected_locale() -> str:
    selected = request.accept_languages.best_match(
        current_app.config['LANGUAGES']
    )
    print(request.accept_languages, current_app.config["LANGUAGES"], selected)
    return selected


def flatten(a: typing.Iterable, levels: int = 1) -> typing.Iterable:
    for i in range(levels):
        a = itertools.chain(*a)
    return a


def circle_name(c: typing.Any) -> str:
    if c.id_ == "default" and c.name == "default":
        return _("Main")
    return c.name


def init_templating(app: quart.Quart) -> None:
    app.template_filter("repr")(repr)
    app.template_filter("format_datetime")(flask_babel.format_datetime)
    app.template_filter("format_date")(flask_babel.format_date)
    app.template_filter("format_time")(flask_babel.format_time)
    app.template_filter("format_timedelta")(flask_babel.format_timedelta)
    app.template_filter("flatten")(flatten)
    app.template_filter("circle_name")(circle_name)


def generate_error_id() -> str:
    return base64.b32encode(secrets.token_bytes(8)).decode(
        "ascii"
    ).rstrip("=")
