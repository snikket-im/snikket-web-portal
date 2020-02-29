import quart.flask_patch

from quart import Quart, session, request, render_template, redirect, url_for

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

from .user import user_bp
app.register_blueprint(user_bp)
