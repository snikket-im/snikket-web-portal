import base64
import binascii

import quart.flask_patch

from quart import (
    Quart, session, request, render_template, redirect, url_for, Response
)

from .prosodyclient import client

app = Quart(__name__)
app.config.from_envvar("SNIKKET_WEB_CONFIG")

client.init_app(app)
client.default_login_redirect = "login"


@app.route("/login", methods=["GET", "POST"])
async def login():
    if client.has_session:
        return redirect(url_for('user.index'))

    if request.method == "POST":
        form = await request.form
        jid = form["address"]
        password = form["password"]
        await client.login(jid, password)
        return redirect(url_for('user.index'))

    return await render_template("login.html")


@app.route("/")
async def home():
    if client.has_session:
        return redirect(url_for('user.index'))

    return redirect(url_for('login'))


@app.route("/meta/about.html")
async def about():
    return await render_template("about.html")


@app.route("/meta/demo.html")
async def demo():
    return await render_template("demo.html")


def repad(s):
    return s + "=" * (4 - len(s) % 4)


@app.route("/avatar/<from_>/<code>")
async def avatar(from_, code):
    try:
        etag = request.headers["if-none-match"]
    except KeyError:
        etag = None

    address = base64.urlsafe_b64decode(repad(from_)).decode("utf-8")
    info = await client.get_avatar(address, metadata_only=True)
    bin_hash = binascii.a2b_hex(info["sha1"])
    new_etag = base64.urlsafe_b64encode(bin_hash).decode("ascii").rstrip("=")

    headers = {
        "ETag": new_etag,
    }

    if etag is not None:
        if new_etag == etag:
            return Response(
                [],
                304,
                content_type=info["type"], headers=headers
            )

    data = await client.get_avatar_data(address, info["sha1"])
    return Response(data, content_type=info["type"], headers=headers)


@app.context_processor
def proc():
    def url_for_avatar(entity, hash_, **kwargs):
        return url_for(
            "avatar",
            from_=base64.urlsafe_b64encode(entity.encode("utf-8")).decode("ascii").rstrip("="),
            code=base64.urlsafe_b64encode(binascii.a2b_hex(hash_)[:8]).decode("ascii").rstrip("="),
            **kwargs
        )

    return {
        "url_for_avatar": url_for_avatar
    }


from .user import user_bp  # NOQA
app.register_blueprint(user_bp)
