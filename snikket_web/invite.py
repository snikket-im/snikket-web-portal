import pathlib
import typing
import urllib.parse

import aiohttp

import quart.flask_patch
from quart import (
    Blueprint,
    current_app,
    render_template,
    redirect,
    request,
    url_for,
    session as http_session,
)

import wtforms

from flask_babel import lazy_gettext as _l, gettext

from .infra import client, selected_locale, BaseForm


bp = Blueprint("invite", __name__)


INVITE_SESSION_JID = "invite-session-jid"

MAX_IMPORT_DATA_SIZE = 5*1024*1024  # 5MB
SUPPORTED_IMPORT_TYPES = ["application/xml", "text/xml"]

EIMPORTTOOBIG = _l("The account data you tried to import is too large to"
                   " upload. Please contact your Snikket operator.")

# https://play.google.com/store/apps/details?id=org.snikket.android&referrer={uri|urlescape}&pcampaignid=pcampaignidMKT-Other-global-all-co-prtnr-py-PartBadge-Mar2515-1


def apple_store_badge() -> str:
    locale = selected_locale()
    filename = "{}.svg".format(locale)
    static_path = pathlib.Path(__file__).parent / "static" / "img" / "apple"
    if (static_path / filename).exists():
        return url_for("static", filename="img/apple/{}".format(filename))
    return url_for("static", filename="img/apple/en.svg")


@bp.context_processor
def context() -> typing.Mapping[str, typing.Any]:
    return {
        "apple_store_badge": apple_store_badge,
    }


@bp.route("/<id_>")
async def view_old(id_: str) -> quart.Response:
    return redirect(url_for(".view", id_=id_))


@bp.route("/<id_>/")
async def view(id_: str) -> typing.Union[quart.Response,
                                         typing.Tuple[str, int],
                                         str]:
    try:
        invite = await client.get_public_invite_by_id(id_)
    except aiohttp.ClientResponseError as exc:
        if exc.status == 404:
            # invite expired
            return await render_template("invite_invalid.html"), 404
        raise

    if invite.reset_localpart is not None:
        return await render_template(
            "invite_reset_view.html",
            invite=invite,
            invite_id=id_,
            account_jid="{}@{}".format(invite.reset_localpart, invite.domain)
        )

    play_store_url = (
        "https://play.google.com/store/apps/details?" +
        urllib.parse.urlencode(
            (
                ("id", "org.snikket.android"),
                ("referrer", invite.xmpp_uri),
                ("pcampaignid",
                 "pcampaignidMKT-Other-global-all-co-prtnr-py-"
                 "PartBadge-Mar2515-1"),
            ),
        )
    )
    apple_store_url = current_app.config["APPLE_STORE_URL"]

    body = await render_template(
        "invite_view.html",
        invite=invite,
        play_store_url=play_store_url,
        apple_store_url=apple_store_url,
        f_droid_url="market://details?id=org.snikket.android",
        invite_id=id_,
    )
    return quart.Response(
        body,
        headers={
            "Link": "<{}> rel=\"alternate\"".format(invite.xmpp_uri),
        }
    )


class RegisterForm(BaseForm):
    localpart = wtforms.StringField(
        _l("Username"),
    )

    password = wtforms.PasswordField(
        _l("Password"),
    )

    password_confirm = wtforms.PasswordField(
        _l("Confirm password"),
        validators=[wtforms.validators.InputRequired(),
                    wtforms.validators.EqualTo(
                        "password",
                        _l("The passwords must match.")
                    )]
    )

    action_register = wtforms.SubmitField(
        _l("Create account")
    )


@bp.route("/<id_>/register", methods=["GET", "POST"])
async def register(id_: str) -> typing.Union[str, quart.Response]:
    try:
        invite = await client.get_public_invite_by_id(id_)
    except aiohttp.ClientResponseError as exc:
        if exc.status == 404:
            return redirect(url_for(".view", id_=id_))

    if invite.reset_localpart is not None:
        return redirect(url_for(".reset", id_=id_))
    form = RegisterForm()

    if form.validate_on_submit():
        # log the user in? show a guide? no idea.
        try:
            jid = await client.register_with_token(
                username=form.localpart.data,
                password=form.password.data,
                token=id_,
            )
        except aiohttp.ClientResponseError as exc:
            if exc.status == 409:
                form.localpart.errors.append(
                    _l("That username is already taken.")
                )
            elif exc.status == 403:
                form.localpart.errors.append(
                    _l("Registration was declined for unknown reasons.")
                )
            elif exc.status == 400:
                form.localpart.errors.append(
                    _l("The username is not valid.")
                )
            elif exc.status == 404:
                return redirect(url_for(".view", id_=id_))
            else:
                raise
        else:
            http_session[INVITE_SESSION_JID] = jid
            await client.login(jid, form.password.data)
            return redirect(url_for(".success"))

    return await render_template(
        "invite_register.html",
        invite=invite,
        form=form,
    )


class ResetForm(BaseForm):
    password = wtforms.PasswordField(
        _l("Password"),
    )

    password_confirm = wtforms.PasswordField(
        _l("Confirm password"),
        validators=[wtforms.validators.InputRequired(),
                    wtforms.validators.EqualTo(
                        "password",
                        _l("The passwords must match.")
                    )]
    )

    action_reset = wtforms.SubmitField(
        _l("Change password")
    )


@bp.route("/<id_>/reset", methods=["GET", "POST"])
async def reset(id_: str) -> typing.Union[str, quart.Response]:
    try:
        invite = await client.get_public_invite_by_id(id_)
    except aiohttp.ClientResponseError as exc:
        if exc.status == 404:
            return redirect(url_for(".view", id_=id_))

    if invite.reset_localpart is None:
        return redirect(url_for(".register", id_=id_))

    form = ResetForm()

    if form.validate_on_submit():
        # log the user in? show a guide? no idea.
        try:
            jid = await client.register_with_token(
                username=invite.reset_localpart,
                password=form.password.data,
                token=id_,
            )
        except aiohttp.ClientResponseError as exc:
            if exc.status == 403:
                form.localpart.errors.append(
                    _l("Registration was declined for unknown reasons.")
                )
            elif exc.status == 404:
                return redirect(url_for(".view", id_=id_))
            else:
                raise
        else:
            http_session[INVITE_SESSION_JID] = jid
            return redirect(url_for(".reset_success"))

    return await render_template(
        "invite_reset.html",
        invite=invite,
        form=form,
    )


class DataImportForm(BaseForm):
    account_data_file = wtforms.FileField(
        _l("Account data file")
    )

    action_import = wtforms.SubmitField(
        _l("Import data")
    )


@bp.route("/success", methods=["GET", "POST"])
@client.require_session()
async def success() -> str:
    form = DataImportForm()
    if form.validate_on_submit():
        ok = True
        file_info = (await request.files).get(form.account_data_file.name)
        if file_info is not None:
            mimetype = file_info.mimetype
            data = file_info.stream.read()
            if len(data) > MAX_IMPORT_DATA_SIZE:
                form.account_data_file.errors.append(EIMPORTTOOBIG)
                ok = False
            elif mimetype not in SUPPORTED_IMPORT_TYPES:
                form.account_data_file.errors.append(
                    # not breaking the line here to avoid extract
                    # translations failing (defensive)
                    gettext("The account data you tried to import is in an unknown format. Please upload an XML file in XEP-0227 format (provided format: %(mimetype)s).", mimetype=mimetype),  # noqa:E501
                )
                ok = False
            elif len(data) > 0:
                await client.import_account_data(data)

        if ok:
            # Re-render success page, this time with no import option
            return await render_template(
                "invite_success.html",
                jid=http_session.get(INVITE_SESSION_JID, ""),
                migration_success=True,
                    )

    return await render_template(
        "invite_success.html",
        jid=http_session.get(INVITE_SESSION_JID, ""),
        migration_success=False,
        form=form,
        max_import_size=MAX_IMPORT_DATA_SIZE,
        import_too_big_warning_header=_l("Error"),
        import_too_big_warning=EIMPORTTOOBIG,
    )


@bp.route("/success/reset", methods=["GET", "POST"])
async def reset_success() -> str:
    return await render_template(
        "invite_reset_success.html",
        jid=http_session.get(INVITE_SESSION_JID, ""),
    )


@bp.route("/-")
async def index() -> quart.Response:
    return redirect(url_for("index"))
