import asyncio
import dataclasses
import enum
import functools
import hashlib
import logging
import secrets
import types
import typing
import typing_extensions

from datetime import datetime, timezone

import aiohttp
from aiohttp import BasicAuth

import xml.etree.ElementTree as ET

from quart import (
    current_app, session as http_session, abort, redirect,
    url_for,
)
import quart

from flask import g as _app_ctx_stack

import werkzeug.exceptions

from . import xmpputil
from .xmpputil import split_jid


SCOPE_RESTRICTED = "prosody:restricted"
SCOPE_DEFAULT = "prosody:registered"
SCOPE_ADMIN = "prosody:admin"


T = typing.TypeVar("T")


@dataclasses.dataclass(frozen=True)
class TokenInfo:
    token: str
    scopes: typing.Collection[str]


@dataclasses.dataclass(frozen=True)
class UserDeletionRequestInfo:
    deleted_at: datetime
    pending_until: datetime

    @classmethod
    def from_api_response(
            cls,
            data: typing.Optional[typing.Mapping[str, typing.Any]],
            ) -> typing.Optional["UserDeletionRequestInfo"]:
        if data is None:
            return None
        return cls(
            deleted_at=datetime.fromtimestamp(
                data["deleted_at"],
                tz=timezone.utc
            ),
            pending_until=datetime.fromtimestamp(
                data["pending_until"],
                tz=timezone.utc
            )
        )


@dataclasses.dataclass(frozen=True)
class AvatarMetadata:
    bytes: int
    hash: str
    type: str
    width: typing.Optional[int]
    height: typing.Optional[int]

    @classmethod
    def from_api_response(
        cls,
        data: typing.Mapping[str, typing.Any],
    ) -> "AvatarMetadata":
        return cls(
            hash=data["hash"],
            bytes=data["bytes"],
            type=data["type"],
            width=data.get("width") or None,
            height=data.get("height") or None,
        )


@dataclasses.dataclass(frozen=True)
class AdminUserInfo:
    localpart: str
    display_name: typing.Optional[str]
    email: typing.Optional[str]
    phone: typing.Optional[str]
    roles: typing.Optional[typing.List[str]]
    enabled: bool
    last_active: typing.Optional[int]
    deletion_request: typing.Optional[UserDeletionRequestInfo]
    avatar_info: typing.List[AvatarMetadata]

    @property
    def has_admin_role(self) -> bool:
        return bool(self.roles and "prosody:admin" in self.roles)

    @property
    def has_restricted_role(self) -> bool:
        return bool(self.roles and "prosody:restricted" in self.roles)

    @classmethod
    def from_api_response(
            cls,
            data: typing.Mapping[str, typing.Any],
            ) -> "AdminUserInfo":
        try:
            roles: typing.Optional[typing.List[str]] = [data["role"]]
            assert roles is not None  # make mypy happy
            roles.extend(data.get("secondary_roles", []))
        except KeyError:
            roles = data.get("roles")
        avatar_info: typing.List[AvatarMetadata] = []
        for avatar in data.get("avatar_info", []):
            # Ignore somehow broken avatars.
            try:
                avatar_metadata = AvatarMetadata.from_api_response(avatar)
                avatar_info.append(avatar_metadata)
            except KeyError:
                pass
        return cls(
            localpart=data["username"],
            display_name=data.get("display_name") or None,
            email=data.get("email") or None,
            phone=data.get("phone") or None,
            roles=roles,
            enabled=data.get("enabled", True),
            last_active=data.get("last_active") or None,
            deletion_request=UserDeletionRequestInfo.from_api_response(
                data.get("deletion_request")
            ),
            avatar_info=avatar_info,
        )


class InviteType(enum.Enum):
    REGISTER = "register"
    ROSTER = "roster"


@dataclasses.dataclass(frozen=True)
class AdminInviteInfo:
    id_: str
    type_: InviteType
    jid: typing.Optional[str]
    token: str
    xmpp_uri: typing.Optional[str]
    landing_page: typing.Optional[str]
    created_at: datetime
    expires: datetime
    reusable: bool
    group_ids: typing.Collection[str]
    role_names: typing.Collection[str]
    is_reset: bool
    note: typing.Optional[str]

    @classmethod
    def from_api_response(
            cls,
            data: typing.Mapping[str, typing.Any],
            ) -> "AdminInviteInfo":
        return cls(
            id_=data["id"],
            created_at=datetime.utcfromtimestamp(data["created_at"]),
            expires=datetime.utcfromtimestamp(data["expires"]),
            type_=InviteType(data["type"]),
            jid=data["jid"],
            token=data["id"],
            xmpp_uri=data.get("xmpp_uri"),
            landing_page=data.get("landing_page"),
            group_ids=data.get("groups", []),
            role_names=data.get("roles", []),
            reusable=data["reusable"],
            is_reset=data.get("reset", False),
            note=data.get("note"),
        )


@dataclasses.dataclass(frozen=True)
class AdminGroupChatInfo:
    id_: str
    jid: str
    name: str

    @classmethod
    def from_api_response(
            cls,
            data: typing.Mapping[str, typing.Any],
            ) -> "AdminGroupChatInfo":
        return cls(
            id_=data["id"],
            jid=data["jid"],
            name=data.get("name", ""),
        )


@dataclasses.dataclass(frozen=True)
class AdminGroupInfo:
    id_: str
    name: str
    members: typing.Collection[str]
    chats: typing.Collection[AdminGroupChatInfo]

    @classmethod
    def from_api_response(
            cls,
            data: typing.Mapping[str, typing.Any],
            ) -> "AdminGroupInfo":
        return cls(
            id_=data["id"],
            name=data["name"],
            members=data.get("members", []),
            chats=[
                AdminGroupChatInfo.from_api_response(x)
                for x in data.get("chats", [])
            ]
        )


@dataclasses.dataclass(frozen=True)
class PublicInviteInfo:
    inviter: typing.Optional[str]
    xmpp_uri: str
    reset_localpart: typing.Optional[str]
    domain: str

    @classmethod
    def from_api_response(
            cls,
            data: typing.Mapping[str, typing.Any],
            ) -> "PublicInviteInfo":
        return cls(
            inviter=data.get("inviter") or None,
            xmpp_uri=data["uri"],
            reset_localpart=data.get("reset", None),
            domain=data["domain"],
        )


class HTTPSessionManager:
    def __init__(self, app_context_attribute: str):
        self._app_context_attribute = app_context_attribute

    async def _create(self) -> aiohttp.ClientSession:
        return aiohttp.ClientSession(headers={
            "Accept": "application/json",
            "Host": current_app.config["SNIKKET_DOMAIN"],
        })

    async def teardown(self, exc: typing.Optional[BaseException]) -> None:
        app_ctx = _app_ctx_stack
        try:
            session = getattr(app_ctx, self._app_context_attribute)
        except AttributeError:
            return

        exc_type: typing.Optional[typing.Type[BaseException]]
        if exc is not None:
            exc_type = type(exc)
            traceback = getattr(exc, "__traceback__", None)
        else:
            exc_type = None
            traceback = None

        await session.__aexit__(exc_type, exc, traceback)

    async def __aenter__(self) -> aiohttp.ClientSession:
        app_ctx = _app_ctx_stack
        try:
            return getattr(app_ctx, self._app_context_attribute)
        except AttributeError:
            pass

        session_object = await self._create()
        session = await session_object.__aenter__()
        setattr(app_ctx, self._app_context_attribute, session)
        return session

    async def __aexit__(
            self,
            exc_type: typing.Optional[typing.Type[BaseException]],
            exc_value: typing.Optional[BaseException],
            traceback: typing.Optional[types.TracebackType],
            ) -> None:
        # we do nothing on aexit, since the session will be kept alive until
        # the application context is torn down in teardown.
        pass


class HTTPAuthSessionManager(HTTPSessionManager):
    def __init__(
            self,
            app_context_attribute: str,
            session_token_key: str):
        super().__init__(app_context_attribute)
        self._session_token_key = session_token_key

    async def _create(self) -> aiohttp.ClientSession:
        try:
            token = http_session[self._session_token_key]
        except KeyError:
            raise abort(401, "no token")

        return aiohttp.ClientSession(
            headers={
                "Authorization": "Bearer {}".format(token),
                "Accept": "application/json",
                "Host": current_app.config["SNIKKET_DOMAIN"],
            }
        )


class AuthSessionProvider(typing_extensions.Protocol):
    _auth_session: HTTPAuthSessionManager


def autosession(
        f: typing.Callable[..., typing.Coroutine[typing.Any, typing.Any, T]]
        ) -> typing.Callable[...,
                             typing.Coroutine[typing.Any, typing.Any, T]]:
    @functools.wraps(f)
    async def wrapper(
            self: AuthSessionProvider,
            *args: typing.Any,
            session: typing.Optional[aiohttp.ClientSession] = None,
            **kwargs: typing.Any) -> T:
        if session is None:
            async with self._auth_session as session:
                return (await f(self, *args, session=session, **kwargs))
        return (await f(self, *args, session=session, **kwargs))
    return wrapper


class ProsodyClient:
    CTX_PLAIN_SESSION = "_ProsodyClient__session"
    CTX_AUTH_SESSION = "_ProsodyClient__auth_session"
    CONFIG_ENDPOINT = "PROSODY_ENDPOINT"
    SESSION_TOKEN = "prosody_access_token"
    SESSION_CACHED_SCOPE = "prosody_scope_cache"
    SESSION_ADDRESS = "prosody_jid"

    def __init__(self, app: typing.Optional[quart.Quart] = None):
        self._default_login_redirect: typing.Optional[str] = None
        self._plain_session = HTTPSessionManager(self.CTX_PLAIN_SESSION)
        self._auth_session = HTTPAuthSessionManager(self.CTX_AUTH_SESSION,
                                                    self.SESSION_TOKEN)
        self.logger = logging.getLogger(
            ".".join([__name__, type(self).__qualname__])
        )
        self.app = app
        if app is not None:
            self.init_app(app)

        self._client_info = None

    @property
    def default_login_redirect(self) -> typing.Optional[str]:
        return self._default_login_redirect

    @default_login_redirect.setter
    def default_login_redirect(self, v: str) -> None:
        self._default_login_redirect = v

    def init_app(self, app: quart.Quart) -> None:
        app.config[self.CONFIG_ENDPOINT]
        app.teardown_appcontext(self._plain_session.teardown)
        app.teardown_appcontext(self._auth_session.teardown)

    @property
    def _endpoint_base(self) -> str:
        return current_app.config[self.CONFIG_ENDPOINT]

    @property
    def _login_endpoint(self) -> str:
        return "{}/oauth2/token".format(self._endpoint_base)

    @property
    def _revoke_endpoint(self) -> str:
        return "{}/oauth2/revoke".format(self._endpoint_base)

    @property
    def _rest_endpoint(self) -> str:
        return "{}/rest".format(self._endpoint_base)

    @property
    def _register_client_endpoint(self) -> str:
        return "{}/oauth2/register".format(self._endpoint_base)

    def _admin_v1_endpoint(self, subpath: str) -> str:
        return "{}/admin_api{}".format(self._endpoint_base, subpath)

    def _public_v1_endpoint(self, subpath: str) -> str:
        return "{}/register_api{}".format(self._endpoint_base, subpath)

    def _xep227_endpoint(self, subpath: str) -> str:
        return "{}/xep227{}".format(self._endpoint_base, subpath)

    async def _oauth2_bearer_token(self,
                                   session: aiohttp.ClientSession,
                                   jid: str,
                                   password: str) -> TokenInfo:
        if not self.is_client_registered():
            self.logger.debug("registering oauth client...")
            await self.register_client()
            self.logger.debug("registered client!")
        request = aiohttp.FormData()
        request.add_field("grant_type", "password")
        request.add_field("username", jid.split("@")[0])
        request.add_field("password", password)
        request.add_field(
            "scope",
            " ".join([SCOPE_RESTRICTED, SCOPE_DEFAULT, SCOPE_ADMIN])
        )

        auth = BasicAuth(
            login=self._client_info["client_id"],
            password=self._client_info["client_secret"],
        )

        self.logger.debug("sending OAuth2 request (payload omitted)")
        async with session.post(self._login_endpoint, auth=auth, data=request) as resp:
            auth_status = resp.status
            auth_info: typing.Mapping[str, str] = (await resp.json())

            if auth_status in [400, 401]:
                self.logger.warning("oauth2 error: %r", auth_info)
                # OAuth2 spec says that’s what can happen when some stuff is
                # wrong.
                # we have to interpret the JSON further
                if auth_info["error"] == "invalid_grant":
                    raise abort(401)

            if auth_status == 200:
                token_type = auth_info["token_type"]
                self.logger.debug("oauth2 success: token_type=%r", token_type)
                if token_type != "bearer":
                    raise NotImplementedError(
                        "unsupported token type: {!r}".format(
                            auth_info["token_type"]
                        )
                    )
                return TokenInfo(
                    token=auth_info["access_token"],
                    scopes=auth_info["scope"].split(),
                )

            raise RuntimeError(
                "unexpected authentication reply: ({}) {!r}".format(
                    auth_status, auth_info
                )
            )

    def _store_token_in_session(self, token_info: TokenInfo) -> None:
        http_session[self.SESSION_TOKEN] = token_info.token
        http_session[self.SESSION_CACHED_SCOPE] = " ".join(token_info.scopes)

    def is_client_registered(self):
        return self._client_info is not None

    async def register_client(self):
        self.logger.debug("sending OAuth2 client registration request (payload omitted)")
        registration_data = {
            "client_name": "Snikket web portal",
            "client_uri": "https://{}".format(current_app.config["SNIKKET_DOMAIN"]),
            # This redirect URI is not used, because we use the password grant type.
            # However, we're registering it with a sensible value because 1) Prosody
            # requires us to provide at least one redirect_uri, and 2) if we ever
            # need it in the future, we won't have to re-register.
            "redirect_uris": ["https://{}/login_result".format(current_app.config["SNIKKET_DOMAIN"])],
            "grant_types": ["password"],
            "response_types": ["code"],
        }
        async with self._plain_session as session:
            async with session.post(self._register_client_endpoint, json=registration_data) as resp:
                reg_status = resp.status
                auth_info: typing.Mapping[str, str] = (await resp.json())

                if reg_status != 201:
                        raise RuntimeError(
                            "Failed to register with backend server: ({}): {}",
                            reg_status,
                            await resp.text()
                        )

                self._client_info = await resp.json()


    async def login(self, jid: str, password: str) -> bool:
        async with self._plain_session as session:
            token_info = await self._oauth2_bearer_token(
                session, jid, password,
            )

        self._store_token_in_session(token_info)
        http_session[self.SESSION_ADDRESS] = jid
        return True

    @property
    def session_token(self) -> str:
        try:
            return http_session[self.SESSION_TOKEN]
        except KeyError:
            raise abort(401, "no session")

    @property
    def session_address(self) -> str:
        try:
            return http_session[self.SESSION_ADDRESS]
        except KeyError:
            raise abort(401, "no session")

    @property
    def has_session(self) -> bool:
        return self.SESSION_TOKEN in http_session

    def authenticated_session(self) -> HTTPAuthSessionManager:
        return self._auth_session

    def require_session(
            self,
            redirect_to: typing.Optional[str] = None,
            ) -> typing.Callable[
                [typing.Callable[..., typing.Awaitable[T]]],
                typing.Callable[..., typing.Awaitable[
                    typing.Union[T, quart.Response, werkzeug.Response]]]]:
        def decorator(
                f: typing.Callable[..., typing.Awaitable[T]],
                ) -> typing.Callable[..., typing.Awaitable[
                    typing.Union[T, quart.Response, werkzeug.Response]]]:
            @functools.wraps(f)
            async def wrapped(
                    *args: typing.Any,
                    **kwargs: typing.Any,
                    ) -> typing.Union[T, quart.Response, werkzeug.Response]:
                if not self.has_session or not (await self.test_session()):
                    redirect_to_value = redirect_to
                    if redirect_to_value is not False:
                        redirect_to_value = \
                            redirect_to_value or self._default_login_redirect
                    if not redirect_to_value:
                        raise abort(401, "Not Authorized")
                    return redirect(url_for(redirect_to_value))

                return await f(*args, **kwargs)
            return wrapped
        return decorator

    def require_admin_session(
            self,
            redirect_to: typing.Optional[str] = None,
            ) -> typing.Callable[
                [typing.Callable[..., typing.Awaitable[T]]],
                typing.Callable[..., typing.Awaitable[
                    typing.Union[T, quart.Response, werkzeug.Response]]]]:
        def decorator(
                f: typing.Callable[..., typing.Awaitable[T]],
                ) -> typing.Callable[..., typing.Awaitable[
                    typing.Union[T, quart.Response, werkzeug.Response]]]:
            @functools.wraps(f)
            @self.require_session(redirect_to=redirect_to)
            async def wrapped(
                    *args: typing.Any,
                    **kwargs: typing.Any,
                    ) -> typing.Union[T, quart.Response, werkzeug.Response]:
                if not self.is_admin_session:
                    raise abort(403, "This is not for you.")

                return await f(*args, **kwargs)
            return wrapped
        return decorator

    async def _xml_iq_call(
            self,
            session: aiohttp.ClientSession,
            payload: ET.Element,
            *,
            headers: typing.Optional[typing.Mapping[str, str]] = None,
            sensitive: bool = False,
            ) -> ET.Element:
        final_headers: typing.MutableMapping[str, str] = {}
        if headers is not None:
            final_headers.update(headers)
        final_headers.update({
            "Content-Type": "application/xmpp+xml",
            "Accept": "application/xmpp+xml",
        })
        if not payload.get("id"):
            payload.set("id", secrets.token_hex(8))

        serialised = ET.tostring(payload)
        id_ = payload.get("id")
        self.logger.debug(
            "sending IQ (id=%s): %r",
            id_, "(sensitive)" if sensitive else serialised,
        )
        async with session.post(self._rest_endpoint,
                                headers=final_headers,
                                data=serialised) as resp:
            if resp.status != 200:
                self.logger.debug(
                    "IQ HTTP response (in-reply-to id=%s) with non-OK status "
                    "%s: %s",
                    id_,
                    resp.status,
                    resp.reason,
                )
                abort(resp.status)
            reply_payload = await resp.read()
            self.logger.debug(
                "received IQ (in-reply-to id=%s): %r",
                id_, "(sensitive)" if sensitive else reply_payload,
            )
            return ET.fromstring(reply_payload)

    @autosession
    async def get_user_info(
            self,
            *,
            session: aiohttp.ClientSession,
            ) -> typing.Mapping:
        localpart, domain, _ = split_jid(self.session_address)

        nickname = await self.get_user_nickname(session=session)
        try:
            avatar_info = await self.get_avatar(
                self.session_address,
                metadata_only=True,
                session=session,
            )
            avatar_hash = avatar_info["sha1"]
        except werkzeug.exceptions.HTTPException:
            avatar_hash = None

        return {
            "address": self.session_address,
            "username": localpart,
            "nickname": nickname,
            "display_name": nickname or localpart,
            "avatar_hash": avatar_hash,
            "is_admin": self.is_admin_session,
        }

    @autosession
    async def test_session(self, session: aiohttp.ClientSession) -> bool:
        req = {
            "kind": "iq",
            "type": "get",
            "ping": True,
            "to": self.session_address,
        }

        async with session.post(self._rest_endpoint, json=req) as resp:
            return resp.status == 200

    @autosession
    async def get_server_version(self, session: aiohttp.ClientSession) -> str:
        _, domain, _ = split_jid(self.session_address)
        req = {
            "kind": "iq",
            "type": "get",
            "version": {},
            "to": domain,
        }

        async with session.post(self._rest_endpoint, json=req) as resp:
            if resp.status != 200:
                return "unknwn"
            try:
                return (await resp.json())["version"]["version"]
            except Exception as exc:
                self.logger.debug(
                    "failed to parse prosody version from response"
                    " (%s: %s)",
                    type(exc), exc,
                )
                return "unknown"

    @autosession
    async def get_user_nickname(
            self,
            *,
            session: aiohttp.ClientSession,
            ) -> typing.Optional[str]:
        iq_resp = await self._xml_iq_call(
            session,
            xmpputil.make_nickname_get_request(self.session_address)
        )
        return xmpputil.extract_nickname_get_reply(iq_resp)

    @autosession
    async def set_user_nickname(
            self,
            new_nickname: str,
            *,
            session: aiohttp.ClientSession,
            ) -> None:
        iq_resp = await self._xml_iq_call(
            session,
            xmpputil.make_nickname_set_request(self.session_address,
                                               new_nickname)
        )
        # just to throw errors
        xmpputil.extract_iq_reply(iq_resp)

    @autosession
    async def get_avatar(
            self,
            from_: str,
            metadata_only: bool = False,
            *,
            session: aiohttp.ClientSession,
            ) -> typing.Mapping:
        metadata_resp = await self._xml_iq_call(
            session,
            xmpputil.make_avatar_metadata_request(from_)
        )
        info = xmpputil.extract_avatar_metadata_get_reply(metadata_resp)
        if info is None:
            raise abort(404, "entity has no avatar")

        if not metadata_only:
            info["data"] = await self.get_avatar_data(
                from_, info["sha1"],
                session=session,
            )

        return info

    @autosession
    async def get_avatar_data(
            self,
            from_: str,
            id_: str,
            *,
            session: aiohttp.ClientSession,
            ) -> typing.Optional[bytes]:
        data_resp = await self._xml_iq_call(
            session,
            xmpputil.make_avatar_data_request(from_, id_)
        )
        return xmpputil.extract_avatar_data_get_reply(data_resp)

    @autosession
    async def get_pubsub_node_access_model(
            self,
            to: str,
            node: str,
            default: str,
            *,
            session: aiohttp.ClientSession) -> str:
        config = xmpputil.extract_pubsub_node_config_get_reply(
            await self._xml_iq_call(
                session,
                xmpputil.make_pubsub_node_config_get_request(
                    to,
                    node,
                ),
            )
        )
        try:
            return config[xmpputil.FORM_FIELD_PUBSUB_ACCESS_MODEL][0]
        except (ValueError, KeyError):
            return default

    @autosession
    async def set_pubsub_node_access_model(
            self,
            to: str,
            node: str,
            new_access_model: str,
            *,
            ignore_not_found: bool = False,
            session: aiohttp.ClientSession) -> None:
        try:
            xmpputil.extract_iq_reply(await self._xml_iq_call(
                session,
                xmpputil.make_pubsub_access_model_put_request(
                    to,
                    node,
                    new_access_model,
                )
            ))
        except werkzeug.exceptions.NotFound:
            if ignore_not_found:
                return
            raise

    @autosession
    async def get_nickname_access_model(
            self,
            *,
            session: aiohttp.ClientSession) -> str:
        return await self.get_pubsub_node_access_model(
            self.session_address,
            xmpputil.NODE_USER_NICKNAME,
            "open",
            session=session,
        )

    @autosession
    async def set_nickname_access_model(
            self,
            new_access_model: str,
            *,
            session: aiohttp.ClientSession) -> None:
        await self.set_pubsub_node_access_model(
            self.session_address,
            xmpputil.NODE_USER_NICKNAME,
            new_access_model,
            session=session,
            ignore_not_found=True,
        )

    @autosession
    async def get_avatar_access_model(
            self,
            *,
            session: aiohttp.ClientSession) -> str:
        return await self.get_pubsub_node_access_model(
            self.session_address,
            xmpputil.NODE_USER_AVATAR_METADATA,
            "open",
            session=session,
        )

    @autosession
    async def set_avatar_access_model(
            self,
            new_access_model: str,
            *,
            session: aiohttp.ClientSession) -> None:
        await asyncio.gather(
            self.set_pubsub_node_access_model(
                self.session_address,
                xmpputil.NODE_USER_AVATAR_DATA,
                new_access_model,
                ignore_not_found=True,
                session=session,
            ),
            self.set_pubsub_node_access_model(
                self.session_address,
                xmpputil.NODE_USER_AVATAR_METADATA,
                new_access_model,
                ignore_not_found=True,
                session=session,
            )
        )

    @autosession
    async def get_vcard_access_model(
            self,
            *,
            session: aiohttp.ClientSession) -> str:
        return await self.get_pubsub_node_access_model(
            self.session_address,
            xmpputil.NODE_VCARD,
            "open",
            session=session,
        )

    @autosession
    async def set_vcard_access_model(
            self,
            new_access_model: str,
            *,
            session: aiohttp.ClientSession) -> None:
        await self.set_pubsub_node_access_model(
            self.session_address,
            xmpputil.NODE_VCARD,
            new_access_model,
            session=session,
            ignore_not_found=True,
        )

    @autosession
    async def set_user_avatar(
            self,
            data: bytes,
            mimetype: str,
            *,
            session: aiohttp.ClientSession,
            ) -> None:
        id_ = hashlib.sha1(data).hexdigest()

        data_resp = await self._xml_iq_call(
            session,
            xmpputil.make_avatar_data_set_request(self.session_address,
                                                  data,
                                                  id_)
        )
        xmpputil.extract_iq_reply(data_resp)

        metadata_resp = await self._xml_iq_call(
            session,
            xmpputil.make_avatar_metadata_set_request(
                self.session_address,
                mimetype=mimetype,
                id_=id_,
                size=len(data),
                width=None,
                height=None,
            )
        )
        xmpputil.extract_iq_reply(metadata_resp)

    @autosession
    async def guess_profile_access_model(
            self,
            *,
            session: aiohttp.ClientSession,
            ) -> str:
        access_models = filter(
            lambda x: not isinstance(x, werkzeug.exceptions.NotFound),
            await asyncio.gather(
                self.get_avatar_access_model(session=session),
                self.get_nickname_access_model(session=session),
                self.get_vcard_access_model(session=session),
                return_exceptions=True,
            )
        )

        order = [
            "open",
            "presence",
            "whitelist",
        ]

        worst_index: typing.Optional[int] = None
        for model in access_models:
            if isinstance(model, BaseException):
                raise model
            try:
                index = order.index(model)
            except ValueError:
                index = 0

            if worst_index is None or index < worst_index:
                worst_index = index

        return order[worst_index or 0]

    async def change_password(
            self,
            current_password: str,
            new_password: str,
            ) -> None:
        # we play it safe here and do not use the existing auth session;
        # instead, we do a login on the plain session and use the token we
        # got there, replacing the current session token on the way.

        async with self._plain_session as session:
            token_info = await self._oauth2_bearer_token(
                session,
                self.session_address,
                current_password,
            )
            password_changed = await self._xml_iq_call(
                session,
                xmpputil.make_password_change_request(
                    self.session_address,
                    new_password
                ),
                headers={
                    "Authorization": "Bearer {}".format(token_info.token),
                },
                sensitive=True,
            )
            xmpputil.extract_iq_reply(password_changed)
            # TODO: obtain a new token using the new password to allow the
            # server to expire/revoke all tokens on password change.
            self._store_token_in_session(token_info)

    def _raise_error_from_response(
            self,
            resp: aiohttp.ClientResponse,
            ) -> None:
        if resp.status in [401, 403]:
            abort(403, "request rejected by backend")
        if resp.status == 400:
            abort(500, "request rejected by backend")
        if not 200 <= resp.status < 300:
            resp.raise_for_status()

    @autosession
    async def list_users(
            self,
            *,
            session: aiohttp.ClientSession,
            ) -> typing.Collection[AdminUserInfo]:
        result = []
        async with session.get(self._admin_v1_endpoint("/users")) as resp:
            self._raise_error_from_response(resp)
            for user in await resp.json():
                result.append(AdminUserInfo.from_api_response(user))
        return result

    @autosession
    async def get_user_by_localpart(
            self,
            localpart: str,
            *,
            session: aiohttp.ClientSession,
            ) -> AdminUserInfo:
        async with session.get(
                self._admin_v1_endpoint("/users/{}".format(localpart)),
                ) as resp:
            self._raise_error_from_response(resp)
            return AdminUserInfo.from_api_response(await resp.json())

    @autosession
    async def update_user(
            self,
            localpart: str,
            *,
            display_name: typing.Optional[str],
            role: typing.Optional[str],
            session: aiohttp.ClientSession,
            ) -> None:
        payload: typing.Dict[str, typing.Any] = {
            "username": localpart,
        }
        if display_name is not None:
            payload["display_name"] = display_name
        if role is not None:
            payload["role"] = role

        async with session.put(
                self._admin_v1_endpoint("/users/{}".format(localpart)),
                json=payload,
                ) as resp:
            self._raise_error_from_response(resp)

    @autosession
    async def enable_user_account(
            self,
            localpart: str,
            *,
            session: aiohttp.ClientSession,
            ) -> None:
        async with session.patch(
                self._admin_v1_endpoint("/users/{}".format(localpart)),
                json={
                    "enabled": True,
                },
                ) as resp:
            self._raise_error_from_response(resp)

    @autosession
    async def disable_user_account(
            self,
            localpart: str,
            *,
            session: aiohttp.ClientSession,
            ) -> None:
        async with session.patch(
                self._admin_v1_endpoint("/users/{}".format(localpart)),
                json={
                    "enabled": False,
                },
                ) as resp:
            self._raise_error_from_response(resp)

    @autosession
    async def get_user_debug_info(
            self,
            localpart: str,
            *,
            session: aiohttp.ClientSession,
            ) -> AdminUserInfo:
        async with session.get(
                self._admin_v1_endpoint("/users/{}/debug".format(localpart)),
                ) as resp:
            self._raise_error_from_response(resp)
            return await resp.json()

    @autosession
    async def delete_user_by_localpart(
            self,
            localpart: str,
            *,
            session: aiohttp.ClientSession,
            ) -> None:
        async with session.delete(
                self._admin_v1_endpoint("/users/{}".format(localpart)),
                ) as resp:
            self._raise_error_from_response(resp)

    @autosession
    async def list_invites(
            self,
            *,
            session: aiohttp.ClientSession,
            ) -> typing.Collection[AdminInviteInfo]:
        async with session.get(self._admin_v1_endpoint("/invites")) as resp:
            self._raise_error_from_response(resp)
            return list(map(AdminInviteInfo.from_api_response,
                            await resp.json()))

    @autosession
    async def get_invite_by_id(
            self,
            id_: str,
            *,
            session: aiohttp.ClientSession,
            ) -> AdminInviteInfo:
        async with session.get(
                self._admin_v1_endpoint("/invites/{}".format(id_)),
                ) as resp:
            self._raise_error_from_response(resp)
            return AdminInviteInfo.from_api_response(await resp.json())

    @autosession
    async def delete_invite(
            self,
            id_: str,
            *,
            session: aiohttp.ClientSession,
            ) -> None:
        async with session.delete(
                self._admin_v1_endpoint("/invites/{}".format(id_)),
                ) as resp:
            self._raise_error_from_response(resp)

    @autosession
    async def create_account_invite(
            self,
            *,
            group_ids: typing.Collection[str] = [],
            role_names: typing.Collection[str] = [],
            restrict_username: typing.Optional[str] = None,
            ttl: typing.Optional[int] = None,
            note: typing.Optional[str] = None,
            session: aiohttp.ClientSession,
            ) -> AdminInviteInfo:
        payload: typing.Dict[str, typing.Any] = {}
        payload["groups"] = list(group_ids)
        payload["roles"] = list(role_names)
        if restrict_username is not None:
            payload["username"] = restrict_username
        if ttl is not None:
            payload["ttl"] = ttl
        if note is not None:
            payload["note"] = note

        async with session.post(
                self._admin_v1_endpoint("/invites/account"),
                json=payload) as resp:
            self._raise_error_from_response(resp)
            return AdminInviteInfo.from_api_response(await resp.json())

    @autosession
    async def create_group_invite(
            self,
            *,
            group_ids: typing.Collection[str] = [],
            role_names: typing.Collection[str] = [],
            ttl: typing.Optional[int] = None,
            note: typing.Optional[str] = None,
            session: aiohttp.ClientSession,
            ) -> AdminInviteInfo:
        payload: typing.Dict[str, typing.Any] = {
            "groups": list(group_ids),
            "roles": list(role_names),
        }
        if ttl is not None:
            payload["ttl"] = ttl
        if note is not None:
            payload["note"] = note

        async with session.post(
                self._admin_v1_endpoint("/invites/group"),
                json=payload) as resp:
            self._raise_error_from_response(resp)
            return AdminInviteInfo.from_api_response(await resp.json())

    @autosession
    async def create_password_reset_invite(
            self,
            *,
            localpart: str,
            ttl: typing.Optional[int] = None,
            session: aiohttp.ClientSession,
            ) -> AdminInviteInfo:
        payload: typing.Dict[str, typing.Any] = {
            "username": localpart,
        }
        if ttl is not None:
            payload["ttl"] = ttl

        async with session.post(
                self._admin_v1_endpoint("/invites/reset"),
                json=payload) as resp:
            self._raise_error_from_response(resp)
            return AdminInviteInfo.from_api_response(await resp.json())

    @autosession
    async def create_group(
            self,
            name: str,
            *,
            create_muc: bool = False,
            session: aiohttp.ClientSession,
            ) -> AdminGroupInfo:
        payload = {
            "name": name,
            "create_muc": create_muc,
        }

        async with session.post(
                self._admin_v1_endpoint("/groups"),
                json=payload) as resp:
            self._raise_error_from_response(resp)
            return AdminGroupInfo.from_api_response(await resp.json())

    @autosession
    async def list_groups(
            self,
            *,
            session: aiohttp.ClientSession,
            ) -> typing.Collection[AdminGroupInfo]:
        async with session.get(self._admin_v1_endpoint("/groups")) as resp:
            self._raise_error_from_response(resp)
            return list(map(
                AdminGroupInfo.from_api_response,
                await resp.json(),
            ))

    @autosession
    async def get_group_by_id(
            self,
            id_: str,
            *,
            session: aiohttp.ClientSession,
            ) -> AdminGroupInfo:
        async with session.get(
                self._admin_v1_endpoint("/groups/{}".format(id_)),
                ) as resp:
            self._raise_error_from_response(resp)
            return AdminGroupInfo.from_api_response(await resp.json())

    @autosession
    async def update_group(
            self,
            id_: str,
            *,
            new_name: typing.Optional[str] = None,
            session: aiohttp.ClientSession,
            ) -> None:
        payload = {}
        if new_name is not None:
            payload["name"] = new_name

        async with session.put(
                self._admin_v1_endpoint(
                    "/groups/{}".format(id_)
                ),
                json=payload,
                ) as resp:
            self._raise_error_from_response(resp)

    @autosession
    async def add_group_member(
            self,
            id_: str,
            localpart: str,
            *,
            session: aiohttp.ClientSession,
            ) -> None:
        async with session.put(
                self._admin_v1_endpoint(
                    "/groups/{}/members/{}".format(id_, localpart)
                ),
                ) as resp:
            self._raise_error_from_response(resp)

    @autosession
    async def add_group_chat(
            self,
            id_: str,
            name: str,
            *,
            session: aiohttp.ClientSession,
            ) -> None:

        payload: typing.Dict[str, typing.Any] = {
            "name": name,
        }

        async with session.post(
                self._admin_v1_endpoint(
                    "/groups/{}/chats".format(id_)
                ),
                json=payload,
                ) as resp:
            self._raise_error_from_response(resp)

    @autosession
    async def remove_group_member(
            self,
            id_: str,
            localpart: str,
            *,
            session: aiohttp.ClientSession,
            ) -> None:
        async with session.delete(
                self._admin_v1_endpoint(
                    "/groups/{}/members/{}".format(id_, localpart)
                ),
                ) as resp:
            self._raise_error_from_response(resp)

    @autosession
    async def remove_group_chat(
            self,
            group_id: str,
            chat_id: str,
            *,
            session: aiohttp.ClientSession,
            ) -> None:
        async with session.delete(
                self._admin_v1_endpoint(
                    "/groups/{}/chats/{}".format(group_id, chat_id)
                ),
                ) as resp:
            self._raise_error_from_response(resp)

    @autosession
    async def delete_group(
            self,
            id_: str,
            *,
            session: aiohttp.ClientSession,
            ) -> None:
        async with session.delete(
                self._admin_v1_endpoint("/groups/{}".format(id_)),
                ) as resp:
            self._raise_error_from_response(resp)

    @autosession
    async def export_account_data(
            self,
            *,
            session: aiohttp.ClientSession,
            ) -> typing.Optional[str]:
        async with session.get(
                self._xep227_endpoint("/export?stores=roster,vcard,pep,pep_data"),  # noqa:E501
                ) as resp:
            self._raise_error_from_response(resp)
            if resp.status == 204:
                return None
            return await resp.text()

    @autosession
    async def import_account_data(
            self,
            user_xml: str,
            *,
            session: aiohttp.ClientSession,
            ) -> bool:
        async with session.put(
                self._xep227_endpoint("/import?stores=roster,vcard,pep,pep_data"),  # noqa:E501
                data=user_xml,
                ) as resp:
            self._raise_error_from_response(resp)
            return True

    async def revoke_token(
            self,
            *,
            session: aiohttp.ClientSession) -> None:
        request = aiohttp.FormData()
        request.add_field("token", self.session_token)
        request.add_field("token_type_hint", "access_token")

        async with session.post(self._revoke_endpoint, data=request) as resp:
            resp.raise_for_status()

    async def logout(self) -> None:
        try:
            async with self._plain_session as session:
                await self.revoke_token(session=session)
        except aiohttp.ClientError:
            self.logger.warn("failed to revoke token!",
                             exc_info=True)
        http_session.pop(self.SESSION_TOKEN, None)
        http_session.pop(self.SESSION_ADDRESS, None)
        http_session.pop(self.SESSION_CACHED_SCOPE, None)

    @property
    def is_admin_session(self) -> bool:
        if not self.has_session:
            return False
        scopes = http_session[self.SESSION_CACHED_SCOPE].split()
        return SCOPE_ADMIN in scopes

    async def get_public_invite_by_id(self, id_: str) -> PublicInviteInfo:
        async with self._plain_session as session:
            async with session.get(self._public_v1_endpoint(
                        "/invite/{}".format(id_)
                    )) as resp:
                resp.raise_for_status()
                return PublicInviteInfo.from_api_response(await resp.json())

    async def register_with_token(
            self,
            token: str,
            username: str,
            password: str,
            ) -> str:
        payload = {
            "username": username,
            "password": password,
            "token": token,
        }
        async with self._plain_session as session:
            async with session.post(
                    self._public_v1_endpoint("/register"),
                    json=payload) as resp:
                resp.raise_for_status()
                return (await resp.json())["jid"]

    @autosession
    async def get_system_metrics(
            self,
            *,
            session: aiohttp.ClientSession) -> typing.Mapping:
        async with session.get(
                self._admin_v1_endpoint("/server/metrics"),
                ) as resp:
            if resp.status == 404:
                return {}
            self._raise_error_from_response(resp)
            resp.raise_for_status()
            return await resp.json()

    @autosession
    async def post_announcement(
            self,
            body: str,
            recipients: str,
            *,
            session: aiohttp.ClientSession) -> None:
        recipients_payload: typing.Union[str, typing.Sequence[str]]
        if recipients == "self":
            recipients_payload = [self.session_address]
        else:
            recipients_payload = recipients

        payload = {
            "recipients": recipients_payload,
            "body": body,
        }

        async with session.post(
                self._admin_v1_endpoint("/server/announcement"),
                json=payload) as resp:
            self._raise_error_from_response(resp)
            resp.raise_for_status()
