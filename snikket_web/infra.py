import base64
import itertools
import math
import secrets
import typing

import quart.flask_patch  # noqa:F401
from quart import (
    current_app,
    request,
    g,
)

import flask_babel
import flask_wtf
from flask_babel import _

from . import prosodyclient


client = prosodyclient.ProsodyClient()
client.default_login_redirect = "main.login"

babel = flask_babel.Babel()


BYTE_UNIT_SCALE_MAP = [
    "B",
    "kiB",
    "MiB",
    "GiB",
    "TiB",
]


@babel.localeselector  # type:ignore
def selected_locale() -> str:
    g.language_header_accessed = True
    selected = request.accept_languages.best_match(
        current_app.config['LANGUAGES']
    ) or current_app.config['LANGUAGES'][0]
    return selected


def flatten(a: typing.Iterable, levels: int = 1) -> typing.Iterable:
    for i in range(levels):
        a = itertools.chain(*a)
    return a


def circle_name(c: typing.Any) -> str:
    if c.id_ == "default" and c.name == "default":
        return _("Main")
    return c.name


def format_bytes(n: float) -> str:
    try:
        scale = max(math.floor(math.log(n, 1024)), 0)
    except ValueError:
        scale = 0
    try:
        unit = BYTE_UNIT_SCALE_MAP[scale]
        factor = 1024**scale
    except IndexError:
        unit = "TiB"
        factor = 1024**4
    if factor > 1:
        return "{:.1f} {}".format(n / factor, unit)
    return "{} {}".format(n, unit)


def add_vary_language_header(resp: quart.Response) -> quart.Response:
    if getattr(g, "language_header_accessed", False):
        resp.vary.add("Accept-Language")
    return resp


def init_templating(app: quart.Quart) -> None:
    app.template_filter("repr")(repr)
    app.template_filter("format_datetime")(flask_babel.format_datetime)
    app.template_filter("format_date")(flask_babel.format_date)
    app.template_filter("format_time")(flask_babel.format_time)
    app.template_filter("format_timedelta")(flask_babel.format_timedelta)
    app.template_filter("format_percent")(flask_babel.format_percent)
    app.template_filter("format_bytes")(format_bytes)
    app.template_filter("flatten")(flatten)
    app.template_filter("circle_name")(circle_name)
    app.after_request(add_vary_language_header)


def generate_error_id() -> str:
    return base64.b32encode(secrets.token_bytes(8)).decode(
        "ascii"
    ).rstrip("=")


class BaseForm(flask_wtf.FlaskForm):  # type:ignore
    def __init__(self, *args: typing.Any, **kwargs: typing.Any):
        meta = kwargs["meta"] = dict(kwargs.get("meta", {}))
        if "locales" not in meta:
            locale = flask_babel.get_locale()
            if locale:
                meta["locales"] = [str(locale)]

        super().__init__(*args, **kwargs)
