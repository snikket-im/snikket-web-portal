import functools
import hashlib
import logging
import secrets
import types
import typing

import aiohttp

import xml.etree.ElementTree as ET

from quart import (
    current_app, _app_ctx_stack, session as http_session, abort, redirect,
    url_for,
)
import quart.exceptions

from . import xmpputil
from .xmpputil import split_jid


T = typing.TypeVar("T")


class HTTPSessionManager:
    def __init__(self, app_context_attribute: str):
        self._app_context_attribute = app_context_attribute

    async def _create(self) -> aiohttp.ClientSession:
        return aiohttp.ClientSession(headers={
            "Accept": "application/json",
        })

    async def teardown(self, exc: typing.Optional[BaseException]) -> None:
        app_ctx = _app_ctx_stack.top
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
        app_ctx = _app_ctx_stack.top
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
            }
        )


class AuthSessionProvider(typing.Protocol):
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
    def _rest_endpoint(self) -> str:
        return "{}/rest".format(self._endpoint_base)

    async def _oauth2_bearer_token(self,
                                   session: aiohttp.ClientSession,
                                   jid: str,
                                   password: str) -> None:
        request = aiohttp.FormData()
        request.add_field("grant_type", "password")
        request.add_field("username", jid)
        request.add_field("password", password)

        self.logger.debug("sending OAuth2 request (payload omitted)")
        async with session.post(self._login_endpoint, data=request) as resp:
            auth_status = resp.status
            auth_info = (await resp.json())

            if auth_status in [400, 401]:
                self.logger.debug("oauth2 error: %r", auth_info)
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
                return auth_info["access_token"]

            raise RuntimeError(
                "unexpected authentication reply: ({}) {!r}".format(
                    auth_status, auth_info
                )
            )

    async def login(self, jid: str, password: str) -> bool:
        async with self._plain_session as session:
            token = await self._oauth2_bearer_token(session, jid, password)

        http_session[self.SESSION_TOKEN] = token
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

    def require_session(
            self,
            redirect_to: typing.Optional[str] = None,
            ) -> typing.Callable[
                [typing.Callable[..., typing.Awaitable[T]]],
                typing.Callable[..., typing.Awaitable[
                    typing.Union[T, quart.Response]]]]:
        def decorator(
                f: typing.Callable[..., typing.Awaitable[T]],
                ) -> typing.Callable[..., typing.Awaitable[
                    typing.Union[T, quart.Response]]]:
            @functools.wraps(f)
            async def wrapped(
                    *args: typing.Any,
                    **kwargs: typing.Any,
                    ) -> typing.Union[T, quart.Response]:
                if not self.has_session or not (await self.test_session()):
                    nonlocal redirect_to
                    if redirect_to is not False:
                        redirect_to = \
                            redirect_to or self._default_login_redirect
                    if not redirect_to:
                        raise abort(401, "Not Authorized")
                    return redirect(url_for(redirect_to))

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
                abort(resp.status)
            reply_payload = await resp.read()
            self.logger.debug(
                "received IQ (in-reply-to id=%s): %r",
                id_, "(sensitive)" if sensitive else reply_payload,
            )
            return ET.fromstring(reply_payload)

    async def get_user_info(self) -> typing.Mapping:
        localpart, domain, _ = split_jid(self.session_address)

        async with self._auth_session as session:
            nickname = await self.get_user_nickname(session=session)
            try:
                avatar_info = await self.get_avatar(
                    self.session_address,
                    metadata_only=True,
                    session=session,
                )
                avatar_hash = avatar_info["sha1"]
            except quart.exceptions.HTTPException:
                avatar_hash = None

            return {
                "address": self.session_address,
                "username": localpart,
                "nickname": nickname,
                "display_name": nickname or localpart,
                "avatar_hash": avatar_hash,
            }

    @autosession
    async def test_session(self, session: aiohttp.ClientSession) -> bool:
        req = {
            "kind": "iq",
            "type": "get",
            "ping": True,
            "to": self.session_address,
        }

        async with session.post(self._rest_endpoint, data=req) as resp:
            return resp.status == 200

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

    async def change_password(
            self,
            current_password: str,
            new_password: str,
            ) -> None:
        # we play it safe here and do not use the existing auth session;
        # instead, we do a login on the plain session and use the token we
        # got there, replacing the current session token on the way.

        async with self._plain_session as session:
            token = await self._oauth2_bearer_token(
                session,
                self.session_address,
                current_password,
            )
            await self._xml_iq_call(
                session,
                xmpputil.make_password_change_request(
                    self.session_address,
                    new_password
                ),
                headers={
                    "Authorization": "Bearer {}".format(token),
                },
                sensitive=True,
            )
            # TODO: error handling
            # TODO: obtain a new token using the new password to allow the
            # server to expire/revoke all tokens on password change.
            http_session[self.SESSION_TOKEN] = token

    async def logout(self) -> None:
        # this currently only kills the cookie stuff, we may want to invalidate
        # the token on the server side, toos
        # See-Also: https://issues.prosody.im/1503
        http_session.pop(self.SESSION_TOKEN, None)
        http_session.pop(self.SESSION_ADDRESS, None)


client = ProsodyClient()
