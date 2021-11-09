import json
import resource
import time
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
    abort,
    flash,
    current_app,
)

from flask_babel import lazy_gettext as _l, _

from . import prosodyclient, _version
from .infra import client, circle_name, BaseForm

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@client.require_admin_session()
async def index() -> str:
    show_metrics = current_app.config["SHOW_METRICS"]
    return await render_template(
        "admin_home.html",
        show_metrics=show_metrics,
    )


class PasswordResetLinkPost(BaseForm):
    action_revoke = wtforms.StringField()


@bp.route("/users")
@client.require_admin_session()
async def users() -> str:
    users = sorted(
        await client.list_users(),
        key=lambda x: x.localpart
    )
    invite_form = InvitePost()
    await invite_form.init_choices()
    reset_form = PasswordResetLinkPost()
    return await render_template(
        "admin_users.html",
        users=users,
        reset_form=reset_form,
        invite_form=invite_form,
    )


class EditUserForm(BaseForm):
    localpart = wtforms.StringField(
        _l("Login name"),
    )

    display_name = wtforms.StringField(
        _l("Display name"),
    )

    role = wtforms.RadioField(
        _l("Access Level"),
        choices=[
            ("prosody:restricted", _("Limited")),
            ("prosody:normal", _l("Normal user")),
            ("prosody:admin", _l("Administrator")),
        ],
    )

    action_save = wtforms.SubmitField(
        _l("Update user"),
    )

    action_create_reset = wtforms.SubmitField(
        _l("Create password reset link"),
    )


@bp.route("/user/<localpart>/", methods=["GET", "POST"])
@client.require_admin_session()
async def edit_user(localpart: str) -> typing.Union[quart.Response, str]:
    target_user_info = await client.get_user_by_localpart(localpart)

    form = EditUserForm()
    if form.validate_on_submit():
        if form.action_create_reset.data:
            target_user_info = await client.get_user_by_localpart(localpart)
            reset_link = await client.create_password_reset_invite(
                localpart=localpart,
                ttl=86400,
            )
            await flash(
                _("Password reset link created"),
                "success",
            )
            return redirect(url_for(
                ".user_password_reset_link",
                id_=reset_link.id_,
            ))

        await client.update_user(
            localpart,
            display_name=form.display_name.data,
            roles=[form.role.data],
        )

        await flash(
            _("User information updated."),
            "success",
        )
        return redirect(url_for(".edit_user", localpart=localpart))

    elif request.method == "GET":
        form.localpart.data = target_user_info.localpart
        form.display_name.data = target_user_info.display_name
        if target_user_info.roles:
            form.role.data = target_user_info.roles[0]
        else:
            form.role.data = "prosody:normal"

    return await render_template(
        "admin_edit_user.html",
        target_user=target_user_info,
        form=form,
    )


class DeleteUserForm(BaseForm):
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
            await flash(
                _("User deleted"),
                "success",
            )
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


@bp.route("/users/password-reset/<id_>", methods=["GET", "POST"])
@client.require_admin_session()
async def user_password_reset_link(
        id_: str,
        ) -> typing.Union[str, quart.Response]:
    invite_info = await client.get_invite_by_id(
        id_,
    )
    if invite_info.jid is None:
        await flash(
            _("Password reset link not found"),
            "alert",
        )
        return redirect(url_for(".users"))

    localpart = prosodyclient.split_jid(invite_info.jid)[0]

    form = PasswordResetLinkPost()
    if form.validate_on_submit():
        if form.action_revoke.data:
            await client.delete_invite(id_)
            await flash(
                _("Password reset link deleted"),
                "success",
            )
            return redirect(url_for(".edit_user", localpart=localpart))
        abort(400)

    return await render_template(
        "admin_reset_user_password.html",
        localpart=localpart,
        reset_link=invite_info,
        form=form,
    )


class InvitesListForm(BaseForm):
    action_revoke = wtforms.StringField()


class InvitePost(BaseForm):
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

    type_ = wtforms.RadioField(
        _l("Invitation type"),
        choices=[
            ("account", _l("Individual")),
            ("group", _l("Group")),
        ],
        default="account",
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
        (
            invite
            for invite in await client.list_invites()
            if not invite.is_reset
        ),
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


class InviteForm(BaseForm):
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
        if form.type_.data == "group":
            invite = await client.create_group_invite(
                group_ids=form.circles.data,
                ttl=form.lifetime.data,
            )
        else:
            invite = await client.create_account_invite(
                group_ids=form.circles.data,
                ttl=form.lifetime.data,
            )
        await flash(
            _("Invitation created"),
            "success",
        )
        return redirect(url_for(".edit_invite", id_=invite.id_))
    return await render_template("admin_create_invite.html",
                                 invite_form=form)


@bp.route("/invitation/<id_>", methods=["GET", "POST"])
@client.require_admin_session()
async def edit_invite(id_: str) -> typing.Union[str, quart.Response]:
    try:
        invite_info = await client.get_invite_by_id(id_)
    except aiohttp.ClientResponseError as exc:
        if exc.status == 404:
            await flash(
                _("No such invitation exists"),
                "alert",
            )
            return redirect(url_for(".invitations"))
    circles = await client.list_groups()
    circle_map = {
        circle.id_: circle
        for circle in circles
    }

    form = InviteForm()
    if form.validate_on_submit():
        if form.action_revoke.data:
            await client.delete_invite(id_)
            await flash(
                _("Invitation revoked"),
                "success",
            )
            return redirect(url_for(".invitations"))
        return redirect(url_for(".edit_invite", id_=id_))

    return await render_template(
        "admin_edit_invite.html",
        invite=invite_info,
        now=datetime.utcnow(),
        form=form,
        circle_map=circle_map,
    )


class CirclePost(BaseForm):
    name = wtforms.StringField(
        _l("Name"),
        validators=[wtforms.validators.InputRequired()],
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
        await flash(
            _("Circle created"),
            "success",
        )
        return redirect(url_for(".edit_circle", id_=circle.id_))

    return await render_template(
        "admin_create_circle.html",
        create_form=create_form,
    )


class EditCircleForm(BaseForm):
    name = wtforms.StringField(
        _l("Name"),
        validators=[wtforms.validators.InputRequired()],
    )

    user_to_add = wtforms.SelectField(
        _l("Select user"),
        validate_choice=False,
    )

    action_save = wtforms.SubmitField(
        _l("Update circle")
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
                await flash(
                    _("No such circle exists"),
                    "alert",
                )
                return redirect(url_for(".circles"))
            raise

        users = {
            user.localpart: user
            for user in await client.list_users()
        }
        circle_members = [
            (localpart, users.get(localpart))
            for localpart in sorted(circle.members)
        ]

    form = EditCircleForm()
    form.user_to_add.choices = sorted(
        (localpart, localpart)
        for localpart in users.keys()
        if localpart not in circle.members
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
            await flash(
                _("Circle data updated"),
                "success",
            )
        elif form.action_delete.data:
            await client.delete_group(id_)
            await flash(
                _("Circle deleted"),
                "success",
            )
            return redirect(url_for(".circles"))
        elif form.action_add_user.data:
            if form.user_to_add.data in valid_users:
                await client.add_group_member(
                    id_,
                    form.user_to_add.data,
                )
                await flash(
                    _("User added to circle"),
                    "success",
                )
        elif form.action_remove_user.data:
            await client.remove_group_member(
                id_,
                form.action_remove_user.data,
            )
            await flash(
                _("User removed from circle"),
                "success",
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


_CPU_EPOCH = time.process_time()
_MONOTONIC_EPOCH = time.monotonic()


def get_system_stats() -> typing.MutableMapping[
        str,
        typing.Optional[typing.Union[int, float]]]:
    pagesize = resource.getpagesize()
    my_rss: typing.Optional[int] = None
    try:
        with open("/proc/self/statm") as f:
            stats = f.read().split()
        my_rss = int(stats[1]) * pagesize
    except (ValueError, IndexError, TypeError, OSError):
        pass

    my_cpu = (
        (time.process_time() - _CPU_EPOCH) /
        (time.monotonic() - _MONOTONIC_EPOCH)
    )

    mem_total, mem_available = None, None
    load5: typing.Optional[float] = None

    try:
        with open("/proc/loadavg") as f:
            stats = f.read().split()
        load5 = float(stats[1])
    except (ValueError, IndexError, TypeError, OSError):
        pass

    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    mem_total = int(line.split()[1]) * 1024
                elif line.startswith("MemAvailable"):
                    mem_available = int(line.split()[1]) * 1024
                if mem_total is not None and mem_available is not None:
                    break
    except (ValueError, TypeError, IndexError, OSError):
        pass

    return {
        "portal_rss": my_rss,
        "portal_cpu": my_cpu,
        "load5": load5,
        "mem_total": mem_total,
        "mem_available": mem_available,
    }


class AnnouncementForm(BaseForm):
    text = wtforms.StringField(
        _("Message contents"),
        widget=wtforms.widgets.TextArea(),
        validators=[wtforms.validators.DataRequired()],
    )

    online_only = wtforms.BooleanField(
        _("Only send to online users"),
    )

    action_post_all = wtforms.SubmitField(
        _("Post to all users"),
    )

    action_send_preview = wtforms.SubmitField(
        _("Send preview to yourself"),
    )


@bp.route("/system/", methods=["GET", "POST"])
@client.require_admin_session()
async def system() -> typing.Union[str, quart.Response]:
    form = AnnouncementForm()

    if form.validate_on_submit():
        recipients = "self"
        if form.action_post_all.data:
            if form.online_only.data:
                recipients = "online"
            else:
                recipients = "all"

        await client.post_announcement(
            form.text.data,
            recipients=recipients,
        )
        await flash(
            _("Announcement sent!"),
            "success",
        )
        if recipients != "self":
            # redirect only if not previewing
            return redirect(url_for(".system"))

    version = None
    now = None
    show_metrics = current_app.config["SHOW_METRICS"]
    if show_metrics:
        version = await client.get_server_version()
        now = time.time()
        try:
            prosody_metrics = await client.get_system_metrics()
        except quart.exceptions.NotFound:
            # server does not offer the endpoint for whatever reason -- ignore
            prosody_metrics = {}

        metrics = get_system_stats()
        try:
            prosody_cpu_metrics = prosody_metrics["cpu"]
        except KeyError:
            pass
        else:
            metrics["prosody_cpu"] = (prosody_cpu_metrics["value"] /
                                      (now - prosody_cpu_metrics["since"]))

        try:
            metrics["prosody_rss"] = prosody_metrics["memory"]
        except KeyError:
            pass

        try:
            metrics["prosody_devices"] = prosody_metrics["c2s"]
        except KeyError:
            pass

        for k in list(metrics.keys()):
            if metrics[k] is None:
                # so that defaulting in jinja works
                del metrics[k]
    else:
        metrics = {}

    return await render_template(
        "admin_system.html",
        metrics=metrics,
        version=_version.version,
        prosody_version=version,
        form=form,
        show_metrics=show_metrics,
    )
