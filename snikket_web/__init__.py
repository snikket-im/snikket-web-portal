import base64
import binascii
import logging
import pathlib
import typing

import quart.flask_patch

import quart
from quart import (
    url_for,
)

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


def create_app() -> quart.Quart:
    app = quart.Quart(__name__)
    app.config.setdefault("LANGUAGES", ["de", "en"])
    app.config.from_envvar("SNIKKET_WEB_CONFIG")
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
