import base64
import binascii
import logging
import os
import pathlib
import typing

import aiohttp

import quart.flask_patch

import quart
from quart import (
    url_for,
    render_template,
    current_app,
    redirect,
    jsonify,
)

import werkzeug.exceptions

import environ

from . import colour, infra
from ._version import version  # noqa:F401


async def proc() -> typing.Dict[str, typing.Any]:
    def url_for_avatar(entity: str, hash_: str,
                       **kwargs: typing.Any) -> str:
        return url_for(
            "main.avatar",
            from_=base64.urlsafe_b64encode(
                entity.encode("utf-8"),
            ).decode("ascii").rstrip("="),
            code=base64.urlsafe_b64encode(
                binascii.a2b_hex(hash_)[:8],
            ).decode("ascii").rstrip("="),
            **kwargs
        )

    try:
        user_info = await infra.client.get_user_info()
    except (aiohttp.ClientError, werkzeug.exceptions.HTTPException):
        user_info = {}

    return {
        "url_for_avatar": url_for_avatar,
        "text_to_css": colour.text_to_css,
        "lang": infra.selected_locale(),
        "user_info": user_info,
        "is_in_debug_mode": current_app.debug,
    }


def autosplit(s: typing.Union[str, typing.List[str]]) -> typing.List[str]:
    if isinstance(s, str):
        return s.split()
    return s


async def render_exception_template(
        template: str,
        exc: Exception,
        error_id: str,
        ) -> str:
    more: typing.Dict[str, str] = {}
    if current_app.debug:
        import traceback
        more.update(
            traceback="".join(traceback.format_exception(
                type(exc),
                exc,
                exc.__traceback__,
            )),
        )

    return await render_template(
        template,
        exception_short=str(
            ".".join([
                type(exc).__module__,
                type(exc).__qualname__,
            ]),
        ),
        error_id=error_id,
        **more,
    )


async def backend_error_handler(exc: Exception) -> quart.Response:
    error_id = infra.generate_error_id()
    current_app.logger.error(
        "error_id=%s returning 503 status page for exception",
        error_id,
        exc_info=exc,
    )
    return quart.Response(
        await render_exception_template(
            "backend_error.html",
            exc,
            error_id,
        ),
        status=503,
    )


async def generic_http_error(
        exc: werkzeug.exceptions.HTTPException,
        ) -> quart.Response:
    return quart.Response(
        await render_template(
            "generic_http_error.html",
            status=exc.code,
            description=exc.description,
            name=exc.name,
        ),
        status=exc.code,
    )


async def generic_error_handler(
        exc: Exception,
        ) -> quart.Response:
    error_id = infra.generate_error_id()
    current_app.logger.error(
        "error_id=%s returning 500 status page for exception",
        error_id,
        exc_info=exc,
    )
    return quart.Response(
        await render_exception_template(
            "internal_error.html",
            exc,
            error_id,
        ),
        status=500,
    )


@environ.config(prefix="SNIKKET_WEB")
class AppConfig:
    secret_key = environ.var()
    prosody_endpoint = environ.var()
    domain = environ.var()
    site_name = environ.var("")
    avatar_cache_ttl = environ.var(1800, converter=int)
    languages = environ.var([
        # Keep `en` as the first language, because it is used as a fallback
        # if the language negotiation cannot find another match. It is more
        # likely that users are able to read english (or find a suitable
        # online translator) than, for instance, danish.
        "en",
        "da",
        "de",
        "fr",
        "id",
        "it",
        "pl",
        "ru",
        "sv",
        "uk",
        "zh_Hans_CN",
    ], converter=autosplit)
    apple_store_url = environ.var(
        "https://apps.apple.com/us/app/monal-xmpp-chat/id317711500",
    )
    # Default limit of 1 MiB is what was discovered to be the effective limit
    # in #67, hence we set that here for now.
    # Future versions may change this default, and the standard deployment
    # tools may also very well override it.
    max_avatar_size = environ.var(1024*1024, converter=int)
    show_metrics = environ.bool_var(True)
    tos_uri = environ.var("")
    privacy_uri = environ.var("")
    abuse_email = environ.var("")
    security_email = environ.var("")


_UPPER_CASE = "".join(map(chr, range(ord("A"), ord("Z")+1)))


def create_app() -> quart.Quart:
    try:
        env_init = os.environ["SNIKKET_WEB_PYENV"]
    except KeyError:
        pass
    else:
        import runpy
        init_vars = runpy.run_path(env_init)
        for name, value in init_vars.items():
            if not name:
                continue
            if name[0] not in _UPPER_CASE:
                continue
            os.environ[name] = value

    config = environ.to_config(AppConfig)

    app = quart.Quart(__name__)
    app.config["LANGUAGES"] = config.languages
    app.config["SECRET_KEY"] = config.secret_key
    app.config["PROSODY_ENDPOINT"] = config.prosody_endpoint
    app.config["SNIKKET_DOMAIN"] = config.domain
    app.config["SITE_NAME"] = config.site_name or config.domain
    app.config["AVATAR_CACHE_TTL"] = config.avatar_cache_ttl
    app.config["APPLE_STORE_URL"] = config.apple_store_url
    app.config["MAX_AVATAR_SIZE"] = config.max_avatar_size
    app.config["SHOW_METRICS"] = config.show_metrics
    app.config["TOS_URI"] = config.tos_uri
    app.config["PRIVACY_URI"] = config.privacy_uri
    app.config["ABUSE_EMAIL"] = config.abuse_email
    app.config["SECURITY_EMAIL"] = config.security_email
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    app.context_processor(proc)
    app.register_error_handler(
        aiohttp.ClientConnectorError,
        backend_error_handler,
    )
    app.register_error_handler(
        werkzeug.exceptions.HTTPException,
        generic_http_error,  # type:ignore
    )
    app.register_error_handler(
        Exception,
        generic_error_handler,
    )

    @app.route("/")
    async def index() -> werkzeug.Response:
        if infra.client.has_session:
            return redirect(url_for('user.index'))

        return redirect(url_for('main.login'))

    @app.route("/site.webmanifest")
    def site_manifest() -> quart.Response:
        # this is needed for icons
        return jsonify(
            {
                "name": "Snikket",
                "short_name": "Snikket",
                "icons": [
                    {
                        "src": url_for(
                            "static",
                            filename="img/android-chrome-192x192.png",
                        ),
                        "sizes": "192x192",
                        "type": "image/png"
                    },
                    {
                        "src": url_for(
                            "static",
                            filename="img/android-chrome-256x256.png",
                        ),
                        "sizes": "256x256",
                        "type": "image/png"
                    },
                    {
                        "src": url_for(
                            "static",
                            filename="img/android-chrome-512x512.png",
                        ),
                        "sizes": "512x512",
                        "type": "image/png"
                    },
                ],
                "theme_color": "#fbfdff",
                "background_color": "#fbfdff",
            }
        )

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

    infra.babel.init_app(app)
    infra.client.init_app(app)
    infra.init_templating(app)

    from .main import bp as main_bp
    from .user import bp as user_bp
    from .admin import bp as admin_bp
    from .invite import bp as invite_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(user_bp, url_prefix="/user")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(invite_bp, url_prefix="/invite")

    return app
