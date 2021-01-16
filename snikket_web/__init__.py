import base64
import binascii
import itertools
import logging
import pathlib
import typing

from datetime import datetime, timedelta

import quart.flask_patch

from quart import (
    Quart, request, render_template, redirect, url_for, Response,
    current_app,
)
import quart.exceptions

from flask_wtf import FlaskForm
import wtforms
from flask_babel import Babel, _, lazy_gettext as _l

from . import colour, xmpputil
from .prosodyclient import client

from ._version import version, version_info  # noqa:F401

app = Quart(__name__)
app.config.setdefault("LANGUAGES", ["de", "en"])
app.config.from_envvar("SNIKKET_WEB_CONFIG")

client.init_app(app)
client.default_login_redirect = "login"

babel = Babel(app)


class LoginForm(FlaskForm):
    address = wtforms.TextField(
        _l("Address"),
        validators=[wtforms.validators.InputRequired()],
    )

    password = wtforms.PasswordField(
        _l("Password"),
        validators=[wtforms.validators.InputRequired()],
    )


@babel.localeselector
def selected_locale() -> str:
    return request.accept_languages.best_match(
        current_app.config['LANGUAGES']
    )


@app.route("/login", methods=["GET", "POST"])
async def login() -> typing.Union[str, quart.Response]:
    if client.has_session and (await client.test_session()):
        return redirect(url_for('user.index'))

    form = LoginForm()
    if form.validate_on_submit():
        jid = form.address.data
        localpart, domain, resource = xmpputil.split_jid(jid)
        if not localpart:
            localpart, domain = domain, current_app.config["SNIKKET_DOMAIN"]
        jid = "{}@{}".format(localpart, domain)
        password = form.password.data
        try:
            await client.login(jid, password)
        except quart.exceptions.Unauthorized:
            form.errors.setdefault("", []).append(
                _("Invalid user name or password.")
            )
        else:
            return redirect(url_for('user.index'))

    return await render_template("login.html", form=form)


@app.route("/")
async def home() -> quart.Response:
    if client.has_session:
        return redirect(url_for('user.index'))

    return redirect(url_for('login'))


@app.route("/meta/about.html")
async def about() -> str:
    return await render_template("about.html", version=version)


@app.route("/meta/demo.html")
async def demo() -> str:
    return await render_template("demo.html")


def repad(s: str) -> str:
    return s + "=" * (4 - len(s) % 4)


@app.route("/avatar/<from_>/<code>")
async def avatar(from_: str, code: str) -> quart.Response:
    try:
        etag = request.headers["if-none-match"]
    except KeyError:
        etag = None

    address = base64.urlsafe_b64decode(repad(from_)).decode("utf-8")
    info = await client.get_avatar(address, metadata_only=True)
    bin_hash = binascii.a2b_hex(info["sha1"])
    new_etag = base64.urlsafe_b64encode(bin_hash).decode("ascii").rstrip("=")

    cache_ttl = timedelta(seconds=current_app.config.get(
        "AVATAR_CACHE_TTL",
        300,
    ))

    response = Response("", mimetype=info["type"])
    response.headers["etag"] = new_etag
    # XXX: It seems to me that quart expects localtime(?!) in this field...
    response.expires = datetime.now() + cache_ttl
    response.headers["Content-Security-Policy"] = \
        "frame-ancestors 'none'; default-src 'none'; style-src 'unsafe-inline'"

    if etag is not None and new_etag == etag:
        response.status_code = 304
        return response

    data = await client.get_avatar_data(address, info["sha1"])
    if data is None:
        response.status_code = 404
        return response

    response.status_code = 200

    if request.method == "HEAD":
        response.content_length = len(data)
        return response

    response.set_data(data)
    return response


@app.context_processor
def proc() -> typing.Dict[str, typing.Any]:
    def url_for_avatar(entity: str, hash_: str,
                       **kwargs: typing.Any) -> str:
        return url_for(
            "avatar",
            from_=base64.urlsafe_b64encode(
                entity.encode("utf-8"),
            ).decode("ascii").rstrip("="),
            code=base64.urlsafe_b64encode(
                binascii.a2b_hex(hash_)[:8],
            ).decode("ascii").rstrip("="),
            **kwargs
        )

    return {
        "url_for_avatar": url_for_avatar,
        "text_to_css": colour.text_to_css,
        "lang": selected_locale(),
    }


app.template_filter("repr")(repr)


@app.template_filter("flatten")
def flatten(a: typing.Iterable, levels: int = 1) -> typing.Iterable:
    for i in range(levels):
        a = itertools.chain(*a)
    return a


from .user import user_bp  # NOQA
app.register_blueprint(user_bp)

logging_config = app.config.get("LOGGING_CONFIG")
if logging_config is not None:
    if isinstance(logging_config, dict):
        logging.config.dictConfig(logging_config)
    elif isinstance(logging_config, (bytes, str, pathlib.Path)):
        import toml
        with open(logging_config, "r") as f:
            logging_config = toml.load(f)
        logging.config.dictConfig(logging_config)

else:
    logging.basicConfig(level=logging.WARNING)
    if app.debug:
        logging.getLogger("snikket_web").setLevel(logging.DEBUG)
