import asyncio
import typing

import quart.flask_patch
from quart import Blueprint, render_template, request, redirect, url_for
import quart.exceptions

import wtforms

import flask_wtf

from flask_babel import lazy_gettext as _l, _

from .infra import client

bp = Blueprint('user', __name__)


@bp.context_processor
async def proc() -> typing.Mapping[str, typing.Any]:
    return {"user_info": await client.get_user_info()}


class ChangePasswordForm(flask_wtf.FlaskForm):  # type:ignore
    current_password = wtforms.PasswordField(
        _l("Current password"),
        validators=[wtforms.validators.InputRequired()]
    )

    new_password = wtforms.PasswordField(
        _l("New password"),
        validators=[wtforms.validators.InputRequired()]
    )

    new_password_confirm = wtforms.PasswordField(
        _l("Confirm new password"),
        validators=[wtforms.validators.InputRequired(),
                    wtforms.validators.EqualTo(
                        "new_password",
                        _l("The new passwords must match.")
                    )]
    )


class LogoutForm(flask_wtf.FlaskForm):  # type:ignore
    pass


_ACCESS_MODEL_CHOICES = [
    ("whitelist", _l("Nobody")),
    ("presence", _l("Friends only")),
    ("open", _l("Everyone")),
]


class ProfileForm(flask_wtf.FlaskForm):  # type:ignore
    nickname = wtforms.TextField(
        _l("Display name"),
    )

    avatar = wtforms.FileField(
        _l("Avatar")
    )

    profile_access_model = wtforms.RadioField(
        _l("Profile visibility"),
        choices=_ACCESS_MODEL_CHOICES,
    )


@bp.route("/")
@client.require_session()
async def index() -> str:
    user_info = await client.get_user_info()
    return await render_template("user_home.html", user_info=user_info)


@bp.route('/passwd', methods=["GET", "POST"])
@client.require_session()
async def change_pw() -> typing.Union[str, quart.Response]:
    form = ChangePasswordForm()
    if form.validate_on_submit():
        try:
            await client.change_password(
                form.current_password.data,
                form.new_password.data,
            )
        except quart.exceptions.Unauthorized:
            # server refused current password, set an appropriate error
            form.errors.setdefault(form.current_password.name, []).append(
                _("Incorrect password"),
            )
        else:
            return redirect(url_for("user.change_pw"))

    return await render_template("user_passwd.html", form=form)


@bp.route("/profile", methods=["GET", "POST"])
@client.require_session()
async def profile() -> typing.Union[str, quart.Response]:
    form = ProfileForm()
    if request.method != "POST":
        user_info = await client.get_user_info()
        try:
            profile_access_model = await client.get_nickname_access_model()
        except quart.exceptions.NotFound:
            # avatar node does not exist yet, default the access model to
            # presence
            # that is what will be set if the user now adds a new avatar.
            profile_access_model = "presence"
        form.nickname.data = user_info.get("nickname", "")
        form.profile_access_model.data = profile_access_model

    if form.validate_on_submit():
        user_info = await client.get_user_info()

        file_info = (await request.files).get(form.avatar.name)
        if file_info is not None:
            mimetype = file_info.mimetype
            data = file_info.stream.read()
            if len(data) > 0:
                await client.set_user_avatar(data, mimetype)

        if user_info.get("nickname") != form.nickname.data:
            await client.set_user_nickname(form.nickname.data)

        access_model = form.profile_access_model.data
        await asyncio.gather(
            client.set_avatar_access_model(access_model),
            client.set_vcard_access_model(access_model),
            client.set_nickname_access_model(access_model),
        )

        return redirect(url_for(".profile"))

    return await render_template("user_profile.html", form=form)


@bp.route("/logout", methods=["GET", "POST"])
@client.require_session()
async def logout() -> typing.Union[quart.Response, str]:
    form = LogoutForm()
    if form.validate_on_submit():
        await client.logout()
        return redirect(url_for("main.home"))

    return await render_template("user_logout.html", form=form)
