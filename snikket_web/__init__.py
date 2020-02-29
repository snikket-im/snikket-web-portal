from quart import Quart, session, request, render_template, redirect, url_for

from . import prosodyclient

app = Quart(__name__)
app.config.from_envvar("SNIKKET_WEB_CONFIG")

client = prosodyclient.ProsodyClient(app)
client.default_login_redirect = "login"


@app.route("/", methods=["GET", "POST"])
async def login():
    if client.has_session:
        return redirect(url_for('home'))

    if request.method == "POST":
        form = await request.form
        jid = form["address"]
        password = form["password"]
        await client.login(jid, password)
        return redirect(url_for('home'))

    return await render_template("login.html")


@app.route('/home')
@client.require_session()
async def home():
    user_info = await client.get_user_info()

    return await render_template("home.html", user_info=user_info)
