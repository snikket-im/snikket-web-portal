import typing

from datetime import datetime

import quart.flask_patch

import wtforms
import wtforms.fields.html5

from quart import (Blueprint, render_template, redirect, url_for)
import flask_wtf

from flask_babel import lazy_gettext as _l

from .infra import client

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@client.require_admin_session()
async def index() -> str:
    user_info = await client.get_user_info()
    return await render_template("admin_home.html", user_info=user_info)


@bp.route("/users")
@client.require_admin_session()
async def users() -> str:
    user_info = await client.get_user_info()
    users = sorted(
        await client.list_users(),
        key=lambda x: x.localpart
    )
    return await render_template(
        "admin_users.html",
        users=users,
        user_info=user_info,
    )


class DeleteUserForm(flask_wtf.FlaskForm):  # type:ignore
    action_delete = wtforms.SubmitField(
        _l("Delete user permanently")
    )


@bp.route("/user/<localpart>/delete", methods=["GET", "POST"])
@client.require_admin_session()
async def delete_user(localpart: str) -> typing.Union[str, quart.Response]:
    user_info = await client.get_user_info()
    target_user_info = await client.get_user_by_localpart(localpart)
    form = DeleteUserForm()
    if form.validate_on_submit():
        if form.action_delete.data:
            await client.delete_user_by_localpart(localpart)
        return redirect(url_for(".users"))

    return await render_template(
        "admin_delete_user.html",
        target_user=target_user_info,
        user_info=user_info,
        form=form,
    )


class InvitesListForm(flask_wtf.FlaskForm):  # type:ignore
    action_revoke = wtforms.StringField()

    action_create_invite = wtforms.SubmitField(
        _l("New invitation link")
    )


@bp.route("/invitations", methods=["GET", "POST"])
@client.require_admin_session()
async def invitations() -> typing.Union[str, quart.Response]:
    user_info = await client.get_user_info()
    invites = sorted(
        await client.list_invites(),
        key=lambda x: x.created_at
    )

    form = InvitesListForm()
    if form.validate_on_submit():
        if form.action_revoke.data:
            await client.delete_invite(form.action_revoke.data)
        if form.action_create_invite.data:
            info = await client.create_invite()
            return redirect(url_for(".edit_invite", id_=info.id_))
        return redirect(url_for(".invitations"))

    return await render_template(
        "admin_invites.html",
        user_info=user_info,
        invites=invites,
        now=datetime.utcnow(),
        form=form,
    )


class InviteForm(flask_wtf.FlaskForm):  # type:ignore
    action_revoke = wtforms.SubmitField(
        _l("Revoke")
    )


@bp.route("/invitation/<id_>", methods=["GET", "POST"])
@client.require_admin_session()
async def edit_invite(id_: str) -> typing.Union[str, quart.Response]:
    user_info = await client.get_user_info()
    invite_info = await client.get_invite_by_id(id_)

    form = InviteForm()
    if form.validate_on_submit():
        if form.action_revoke.data:
            await client.delete_invite(id_)
            return redirect(url_for(".invitations"))
        return redirect(url_for(".edit_invite", id_=id_))

    return await render_template(
        "admin_edit_invite.html",
        user_info=user_info,
        invite=invite_info,
        now=datetime.utcnow(),
        form=form,
    )
