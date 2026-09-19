"""
httpOnly session-cookie authentication.

Replaces the removed frontend behavior of auto-logging in with a baked-in analyst
password and storing the JWT in localStorage (readable by any JavaScript on the page).
The browser now authenticates via POST /auth/login, which sets an httpOnly cookie the
browser sends automatically; the token itself is never exposed to JavaScript. Machine
clients keep using the Authorization: Bearer header.
"""
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from starlette.testclient import TestClient

from api.main import app
from core.auth import SESSION_COOKIE_NAME, create_access_token, hash_password
from database.session import AsyncSessionLocal
from models.user import User, UserRole

TEST_PASSWORD = "SessionTest2026!"


@pytest_asyncio.fixture
async def real_user():
    """
    A real, password-hashed user row, created directly in the test database rather
    than relying on the startup-time seed accounts (which only exist when api.main's
    lifespan startup ran, which the isolated test client does not trigger).
    """
    user = User(
        id=uuid.uuid4(),
        email=f"session-{uuid.uuid4().hex[:8]}@yarox.local",
        hashed_password=hash_password(TEST_PASSWORD),
        full_name="Session Test User",
        role=UserRole.ANALYST,
        is_active=True,
    )
    async with AsyncSessionLocal() as session:
        session.add(user)
        await session.commit()
    return user


@pytest.mark.asyncio
async def test_login_sets_httponly_session_cookie_not_in_response_body_only(real_user):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/auth/login", json={"email": real_user.email, "password": TEST_PASSWORD})
    assert res.status_code == 200

    set_cookie = res.headers.get("set-cookie", "")
    assert SESSION_COOKIE_NAME in set_cookie
    assert "HttpOnly" in set_cookie
    assert "samesite=lax" in set_cookie.lower()

    # The token is still returned in the body for machine/API clients that use the
    # Authorization header instead of a browser cookie jar.
    body = res.json()
    assert body["access_token"]
    assert body["email"] == real_user.email


@pytest.mark.asyncio
async def test_cookie_alone_authenticates_without_any_authorization_header(real_user):
    """The full login -> cookie -> authenticated request flow, with no bearer header at all."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        login = await ac.post("/auth/login", json={"email": real_user.email, "password": TEST_PASSWORD})
        assert login.status_code == 200
        assert SESSION_COOKIE_NAME in ac.cookies  # httpx's cookie jar picked it up

        # No Authorization header is set anywhere in this test.
        me = await ac.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == real_user.email


@pytest.mark.asyncio
async def test_wrong_password_is_rejected_and_sets_no_cookie(real_user):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/auth/login", json={"email": real_user.email, "password": "wrong-password"})
    assert res.status_code == 401
    assert SESSION_COOKIE_NAME not in res.headers.get("set-cookie", "")


@pytest.mark.asyncio
async def test_logout_clears_the_cookie_and_revokes_cookie_based_access(real_user):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        await ac.post("/auth/login", json={"email": real_user.email, "password": TEST_PASSWORD})
        assert (await ac.get("/auth/me")).status_code == 200

        logout = await ac.post("/auth/logout")
        assert logout.status_code == 200

        # httpx removes the cookie from its jar when the server sends an expiring Set-Cookie
        after = await ac.get("/auth/me")
    assert after.status_code == 401


@pytest.mark.asyncio
async def test_bearer_header_still_works_for_machine_clients_without_a_cookie(real_user):
    token = create_access_token({"sub": str(real_user.id), "email": real_user.email, "role": real_user.role.value})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/investigations/graph/entities", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_session_cookie_takes_precedence_over_a_different_bearer_token(real_user):
    """
    Verifies the documented precedence (cookie, then header): the cookie identifies a
    real user and the header identifies a nonexistent one. If precedence were ever
    reversed, this would 401 (the header user does not exist) instead of returning the
    cookie user, so a regression here is caught rather than passing by coincidence.
    """
    cookie_token = create_access_token({"sub": str(real_user.id), "email": real_user.email, "role": real_user.role.value})
    header_token = create_access_token({"sub": str(uuid.uuid4()), "email": "does-not-exist@yarox.local", "role": UserRole.ADMIN.value})

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        ac.cookies.set(SESSION_COOKIE_NAME, cookie_token)
        res = await ac.get("/auth/me", headers={"Authorization": f"Bearer {header_token}"})
    assert res.status_code == 200
    assert res.json()["email"] == real_user.email


@pytest.mark.asyncio
async def test_websocket_authenticates_from_the_session_cookie_with_no_query_token(real_user):
    """
    Full-stack: log in for real over HTTP (POST /auth/login, real password check, real
    JWT), then open a WebSocket with the resulting session cookie and no ?token= in the
    URL at all — exactly what the browser does. The cookie is sufficient to authenticate.

    The login itself is done through the async httpx client (consistent with every other
    test here and safe on the pytest-asyncio event loop that the DB engine's connection
    pool is already bound to). Starlette's TestClient drives the WebSocket handshake in
    its own thread/event loop; websocket_endpoint()'s auth path decodes the JWT and reads
    "sub" from its payload without any DB query, so handing it a cookie set directly
    (rather than performing the login through TestClient's own HTTP client) avoids ever
    touching the pooled DB connection from that second event loop.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        login = await ac.post("/auth/login", json={"email": real_user.email, "password": TEST_PASSWORD})
    assert login.status_code == 200
    session_token = login.json()["access_token"]
    assert SESSION_COOKIE_NAME in login.headers.get("set-cookie", "")

    client = TestClient(app)
    client.cookies.set(SESSION_COOKIE_NAME, session_token)
    with client.websocket_connect("/ws/investigations") as ws:
        pass  # a clean connect (no exception) proves the server accepted it


def test_websocket_without_cookie_or_query_token_is_rejected():
    client = TestClient(app)
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/investigations"):
            pass
