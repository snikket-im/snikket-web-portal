import asyncio
import json
import typing

from datetime import datetime

import aiohttp

import quart.flask_patch

import wtforms
import wtforms.fields.html5

from quart import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    request,
)
import flask_wtf

from flask_babel import lazy_gettext as _l

from . import prosodyclient
from .infra import client, circle_name

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@client.require_admin_session()
async def index() -> str:
    return await render_template("admin_home.html")


@bp.route("/users")
@client.require_admin_session()
async def users() -> str:
    users = sorted(
        await client.list_users(),
        key=lambda x: x.localpart
    )
    return await render_template(
        "admin_users.html",
        users=users,
    )


class DeleteUserForm(flask_wtf.FlaskForm):  # type:ignore
    action_delete = wtforms.SubmitField(
        _l("Delete user permanently")
    )


@bp.route("/user/<localpart>/delete", methods=["GET", "POST"])
@client.require_admin_session()
async def delete_user(localpart: str) -> typing.Union[str, quart.Response]:
    target_user_info = await client.get_user_by_localpart(localpart)
    form = DeleteUserForm()
    if form.validate_on_submit():
        if form.action_delete.data:
            await client.delete_user_by_localpart(localpart)
        return redirect(url_for(".users"))

    return await render_template(
        "admin_delete_user.html",
        target_user=target_user_info,
        form=form,
    )


@bp.route("/user/<localpart>/debug")
@client.require_admin_session()
async def debug_user(localpart: str) -> typing.Union[str, quart.Response]:
    target_user_info = await client.get_user_by_localpart(localpart)
    debug_info = json.dumps(
        await client.get_user_debug_info(localpart),
        indent=2,
        sort_keys=True,
    )
    return await render_template(
        "admin_debug_user.html",
        target_user=target_user_info,
        debug_dump=debug_info,
    )


class InvitesListForm(flask_wtf.FlaskForm):  # type:ignore
    action_revoke = wtforms.StringField()


class InvitePost(flask_wtf.FlaskForm):  # type:ignore
    circles = wtforms.SelectMultipleField(
        _l("Invite to circle"),
        # NOTE: This is for when/if we ever support multi-group invites.
        # also see the note in admin_create_invite_form.html
        # option_widget=wtforms.widgets.CheckboxInput(),
        widget=wtforms.widgets.Select(multiple=False),
        validators=[wtforms.validators.InputRequired(
            _l("At least one circle must be selected")
        )],
    )

    lifetime = wtforms.SelectField(
        _l("Valid for"),
        choices=[
            (3600, _l("One hour")),
            (12*3600, _l("Twelve hours")),
            (86400, _l("One day")),
            (7*86400, _l("One week")),
            (28*86400, _l("Four weeks")),
        ],
        default=7*86400,
    )

    reusable = wtforms.BooleanField(
        _l("Allow multiple uses"),
    )

    action_create_invite = wtforms.SubmitField(
        _l("New invitation link")
    )

    async def init_choices(
            self,
            *,
            circles: typing.Optional[typing.Collection[
                prosodyclient.AdminGroupInfo
            ]] = None) -> None:
        if circles is not None:
            self.circles.choices = [
                (circle.id_, circle_name(circle))
                for circle in sorted(circles, key=lambda x: x.name)
            ]
            return
        return await self.init_choices(
            circles=await client.list_groups()
        )


@bp.route("/invitations", methods=["GET", "POST"])
@client.require_admin_session()
async def invitations() -> typing.Union[str, quart.Response]:
    invites = sorted(
        await client.list_invites(),
        key=lambda x: x.created_at,
        reverse=True,
    )
    circles = sorted(
        await client.list_groups(),
        key=lambda x: x.name
    )
    circle_map = {
        circle.id_: circle
        for circle in circles
    }

    invite_form = InvitePost()
    await invite_form.init_choices(circles=circles)

    form = InvitesListForm()
    if form.validate_on_submit():
        if form.action_revoke.data:
            await client.delete_invite(form.action_revoke.data)
        return redirect(url_for(".invitations"))

    return await render_template(
        "admin_invites.html",
        invites=invites,
        invite_form=invite_form,
        now=datetime.utcnow(),
        circle_map=circle_map,
        form=form,
    )


class InviteForm(flask_wtf.FlaskForm):  # type:ignore
    action_revoke = wtforms.SubmitField(
        _l("Revoke")
    )


@bp.route("/invitation/-/new", methods=["POST"])
@client.require_admin_session()
async def create_invite() -> typing.Union[str, quart.Response]:
    form = InvitePost()
    circles = await client.list_groups()
    form.circles.choices = [
        (c.id_, c.name) for c in circles
    ]
    if form.validate_on_submit():
        invite = await client.create_invite(
            group_ids=form.circles.data,
            reusable=form.reusable.data,
            ttl=form.lifetime.data,
        )
        return redirect(url_for(".edit_invite", id_=invite.id_))
    return await render_template("admin_create_invite.html",
                                 invite_form=form)


@bp.route("/invitation/<id_>", methods=["GET", "POST"])
@client.require_admin_session()
async def edit_invite(id_: str) -> typing.Union[str, quart.Response]:
    invite_info = await client.get_invite_by_id(id_)
    circles = await client.list_groups()
    circle_map = {
        circle.id_: circle
        for circle in circles
    }

    form = InviteForm()
    if form.validate_on_submit():
        if form.action_revoke.data:
            await client.delete_invite(id_)
            return redirect(url_for(".invitations"))
        return redirect(url_for(".edit_invite", id_=id_))

    return await render_template(
        "admin_edit_invite.html",
        invite=invite_info,
        now=datetime.utcnow(),
        form=form,
        circle_map=circle_map,
    )


class CirclePost(flask_wtf.FlaskForm):  # type:ignore
    name = wtforms.StringField(
        _l("Name"),
    )

    action_create = wtforms.SubmitField(
        _l("Create circle")
    )


@bp.route("/circles")
@client.require_admin_session()
async def circles() -> str:
    circles = sorted(
        await client.list_groups(),
        key=lambda x: x.name
    )
    invite_form = InvitePost()
    create_form = CirclePost()
    return await render_template(
        "admin_circles.html",
        circles=circles,
        invite_form=invite_form,
        create_form=create_form,
    )


@bp.route("/circle/-/new", methods=["POST"])
@client.require_admin_session()
async def create_circle() -> typing.Union[str, quart.Response]:
    create_form = CirclePost()
    if create_form.validate_on_submit():
        circle = await client.create_group(
            name=create_form.name.data,
        )
        return redirect(url_for(".edit_circle", id_=circle.id_))

    return await render_template(
        "admin_create_circle.html",
        create_form=create_form,
    )


class EditCircleForm(flask_wtf.FlaskForm):  # type:ignore
    name = wtforms.StringField(
        _l("Name"),
        validators=[wtforms.validators.InputRequired()],
    )

    user_to_add = wtforms.SelectField(
        _l("Select user"),
        validate_choice=False,
    )

    action_save = wtforms.SubmitField(
        _l("Apply")
    )

    action_delete = wtforms.SubmitField(
        _l("Delete circle permanently")
    )

    action_remove_user = wtforms.StringField()

    action_add_user = wtforms.SubmitField(
        _l("Add user")
    )


@bp.route("/circle/<id_>", methods=["GET", "POST"])
@client.require_admin_session()
async def edit_circle(id_: str) -> typing.Union[str, quart.Response]:
    async with client.authenticated_session() as session:
        try:
            circle = await client.get_group_by_id(
                id_,
                session=session,
            )
        except aiohttp.ClientResponseError as exc:
            if exc.status == 404:
                return redirect(url_for(".circles"))
            raise

        circle_members = await asyncio.gather(*(
            client.get_user_by_localpart(
                localpart,
                session=session,
            )
            for localpart in sorted(circle.members)
        ))

        users = await client.list_users()

    form = EditCircleForm()
    form.user_to_add.choices = sorted(
        (
            (u.localpart, u.localpart)
            for u in users
            if u.localpart not in circle.members
        ),
        key=lambda x: x[1]
    )
    valid_users = [x[0] for x in form.user_to_add.choices]

    invite_form = InvitePost()
    await invite_form.init_choices()
    invite_form.circles.data = [id_]

    if request.method != "POST":
        form.name.data = circle.name

    if form.validate_on_submit():
        if form.action_save.data:
            await client.update_group(
                id_,
                new_name=form.name.data,
            )
        elif form.action_delete.data:
            await client.delete_group(id_)
            return redirect(url_for(".circles"))
        elif form.action_add_user.data:
            if form.user_to_add.data in valid_users:
                print("is valid")
                await client.add_group_member(
                    id_,
                    form.user_to_add.data,
                )
        elif form.action_remove_user.data:
            await client.remove_group_member(
                id_,
                form.action_remove_user.data,
            )

        return redirect(url_for(".edit_circle", id_=id_))
    else:
        print(form.errors)

    return await render_template(
        "admin_edit_circle.html",
        target_circle=circle,
        form=form,
        circle_members=circle_members,
        invite_form=invite_form,
    )
