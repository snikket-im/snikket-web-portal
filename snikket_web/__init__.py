import base64
import binascii
import logging
import os
import pathlib
import typing

import quart.flask_patch

import quart
from quart import (
    url_for,
)

import environ

from . import colour, infra
from ._version import version, version_info  # noqa:F401


def proc() -> typing.Dict[str, typing.Any]:
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

    return {
        "url_for_avatar": url_for_avatar,
        "text_to_css": colour.text_to_css,
        "lang": infra.selected_locale(),
    }


def autosplit(s: typing.Union[str, typing.List[str]]) -> typing.List[str]:
    if isinstance(s, str):
        return s.split()
    return s


@environ.config(prefix="SNIKKET_WEB")
class AppConfig:
    secret_key = environ.var()
    prosody_endpoint = environ.var()
    domain = environ.var()
    avatar_cache_ttl = environ.var(1800, converter=int)
    languages = environ.var(["de", "en"], converter=autosplit)


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
    app.config["AVATAR_CACHE_TTL"] = config.avatar_cache_ttl

    app.context_processor(proc)

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

    app.register_blueprint(main_bp)
    app.register_blueprint(user_bp, url_prefix="/user")
    app.register_blueprint(admin_bp, url_prefix="/admin")

    return app
