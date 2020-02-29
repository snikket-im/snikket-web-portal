import contextlib
import functools

import aiohttp

from quart import (
    current_app, _app_ctx_stack, session as http_session, abort, redirect,
    url_for,
)


def split_jid(s):
    bare, sep, resource = s.partition("/")
    if not sep:
        resource = None
    localpart, sep, domain = bare.partition("@")
    if not sep:
        domain = localpart
        localpart = None
    return localpart, domain, resource


class HTTPSessionManager:
    def __init__(self, app_context_attribute):
        self._app_context_attribute = app_context_attribute

    async def _create(self) -> aiohttp.ClientSession:
        return aiohttp.ClientSession()

    async def teardown(self, exc):
        app_ctx = _app_ctx_stack.top
        try:
            session = getattr(app_ctx, self._app_context_attribute)
        except AttributeError:
            return

        if exc is not None:
            exc_type = type(exc)
            traceback = getattr(exc.__traceback__, None)
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

    async def __aexit__(self, exc_type, exc_value, traceback):
        # we do nothing on aexit, since the session will be kept alive until
        # the application context is torn down in teardown.
        pass


class HTTPAuthSessionManager(HTTPSessionManager):
    def __init__(self, app_context_attribute, session_token_key):
        super().__init__(app_context_attribute)
        self._session_token_key = session_token_key

    async def _create(self) -> aiohttp.ClientSession:
        try:
            token = http_session[self._session_token_key]
        except KeyError:
            raise abort(401, "no token")

        return aiohttp.ClientSession(
            headers={
                "Authorization": "Bearer {}".format(token)
            }
        )


class ProsodyClient:
    CTX_PLAIN_SESSION = "_ProsodyClient__session"
    CTX_AUTH_SESSION = "_ProsodyClient__auth_session"
    CONFIG_ENDPOINT = "PROSODY_ENDPOINT"
    SESSION_TOKEN = "prosody_access_token"
    SESSION_ADDRESS = "prosody_jid"

    def __init__(self, app=None):
        self._default_login_redirect = None
        self._plain_session = HTTPSessionManager(self.CTX_PLAIN_SESSION)
        self._auth_session = HTTPAuthSessionManager(self.CTX_AUTH_SESSION,
                                                    self.SESSION_TOKEN)
        self.app = app
        if app is not None:
            self.init_app(app)

    @property
    def default_login_redirect(self):
        return self._default_login_redirect

    @default_login_redirect.setter
    def default_login_redirect(self, v):
        self._default_login_redirect = v

    def init_app(self, app):
        app.config[self.CONFIG_ENDPOINT]
        app.teardown_appcontext(self._plain_session.teardown)
        app.teardown_appcontext(self._auth_session.teardown)

    @property
    def _endpoint_base(self):
        return current_app.config[self.CONFIG_ENDPOINT]

    @property
    def _login_endpoint(self):
        return "{}/oauth2/token".format(self._endpoint_base)

    @property
    def _rest_endpoint(self):
        return "{}/rest".format(self._endpoint_base)

    async def login(self, jid: str, password: str):
        request = aiohttp.FormData()
        request.add_field("grant_type", "password")
        request.add_field("username", jid)
        request.add_field("password", password)

        async with self._plain_session as session:
            async with session.post(self._login_endpoint, data=request) as resp:
                auth_status = resp.status
                auth_info = (await resp.json())
                if auth_status == 401:
                    raise ValueError("Invalid credentials")
                elif auth_status == 200:
                    token_type = auth_info["token_type"]
                    if token_type != "bearer":
                        raise NotImplementedError(
                            "unsupported token type: {!r}".format(
                                auth_info["token_type"]
                            )
                        )

                    http_session[self.SESSION_TOKEN] = auth_info["access_token"]
                    http_session[self.SESSION_ADDRESS] = jid
                    return True
                else:
                    raise RuntimeError(
                        "unexpected backend response: {!r}".format(auth_status)
                    )

    @property
    def session_token(self):
        try:
            return http_session[self.SESSION_TOKEN]
        except KeyError:
            raise abort(401, "no session")

    @property
    def session_address(self):
        try:
            return http_session[self.SESSION_ADDRESS]
        except KeyError:
            raise abort(401, "no session")

    @property
    def has_session(self):
        return self.SESSION_TOKEN in http_session

    def require_session(self, redirect_to: str = None):
        def decorator(f):
            @functools.wraps(f)
            async def wrapped(*args, **kwargs):
                if not self.has_session:
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

    async def get_user_info(self):
        localpart, domain, _ = split_jid(self.session_address)

        request = {
            "kind": "iq",
            "to": domain,
            "type": "get",
            "ping": True
        }

        async with self._auth_session as session:
            async with session.post(self._rest_endpoint,
                                    json=request) as resp:
                if resp.status != 200:
                    raise abort(resp.status)

                return {
                    "username": localpart,
                }
