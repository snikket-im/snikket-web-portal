import base64
import binascii
import typing

from datetime import datetime, timedelta

import aiohttp

import quart
import quart.flask_patch
from quart import (
    current_app,
    redirect,
    url_for,
    render_template,
    request,
    Response,
    flash,
)

import babel
import wtforms

import flask_wtf

from flask_babel import lazy_gettext as _l, _

from . import xmpputil, _version
from .infra import client


bp = quart.Blueprint("main", __name__)


class LoginForm(flask_wtf.FlaskForm):  # type:ignore
    address = wtforms.TextField(
        _l("Address"),
        validators=[wtforms.validators.InputRequired()],
    )

    password = wtforms.PasswordField(
        _l("Password"),
        validators=[wtforms.validators.InputRequired()],
    )

    action_signin = wtforms.SubmitField(
        _l("Sign in"),
    )


@bp.route("/-")
async def index() -> quart.Response:
    return redirect(url_for("index"))


ERR_CREDENTIALS_INVALID = _l("Invalid username or password.")


@bp.route("/login", methods=["GET", "POST"])
async def login() -> typing.Union[str, quart.Response]:
    if client.has_session and (await client.test_session()):
        return redirect(url_for('user.index'))

    form = LoginForm()
    if form.validate_on_submit():
        jid = form.address.data
        localpart, domain, resource = xmpputil.split_jid(jid)
        if not localpart:
            localpart, domain = domain, current_app.config["SNIKKET_DOMAIN"]
        if domain != current_app.config["SNIKKET_DOMAIN"]:
            # (a) prosody throws a 400 at us and I prefer to catch that here
            # and (b) I don’t want to pass on this obviously not-for-here
            # password further than necessary.
            form.password.errors.append(ERR_CREDENTIALS_INVALID)
        else:
            jid = "{}@{}".format(localpart, domain)
            password = form.password.data
            try:
                await client.login(jid, password)
            except quart.exceptions.Unauthorized:
                form.password.errors.append(ERR_CREDENTIALS_INVALID)
            else:
                await flash(
                    _("Login successful!"),
                    "success"
                )
                return redirect(url_for('user.index'))

    return await render_template("login.html", form=form)


@bp.route("/meta/about.html")
async def about() -> str:
    version = None
    extra_versions = {}

    if current_app.debug or client.is_admin_session:
        version = _version.version
        extra_versions["Quart"] = quart.__version__
        extra_versions["aiohttp"] = aiohttp.__version__
        extra_versions["babel"] = babel.__version__
        extra_versions["wtforms"] = wtforms.__version__
        extra_versions["flask-wtf"] = flask_wtf.__version__
        try:
            extra_versions["Prosody"] = await client.get_server_version()
        except quart.exceptions.Unauthorized:
            extra_versions["Prosody"] = "unknown"

    return await render_template(
        "about.html",
        version=version,
        extra_versions=extra_versions,
    )


@bp.route("/meta/demo.html")
async def demo() -> str:
    return await render_template("demo.html")


def repad(s: str) -> str:
    return s + "=" * (4 - len(s) % 4)


@bp.route("/avatar/<from_>/<code>")
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

@bp.route("/_health")
async def health() -> str:
    return "OK"
