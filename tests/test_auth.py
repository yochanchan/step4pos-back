from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.db.models import RefreshToken
from app.db.session import AsyncSessionLocal

PASSWORD = "Passw1"


async def signup_user(client, email: str = "user@example.com") -> None:
    response = await client.post(
        "/auth/signup",
        json={
            "email": email,
            "password": PASSWORD,
            "display_name": "Test User",
        },
    )
    assert response.status_code == 201


@pytest.mark.asyncio
async def test_signup_login_and_me_flow(client):
    await signup_user(client)

    login_response = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": PASSWORD},
    )
    assert login_response.status_code == 200
    login_data = login_response.json()
    assert login_data["user"]["email"] == "user@example.com"
    assert "access_token" in login_data

    access_token = login_data["access_token"]
    me_response = await client.get(
        "/auth/me", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert me_response.status_code == 200
    me_data = me_response.json()
    assert me_data["email"] == "user@example.com"
    assert me_data["display_name"] == "Test User"

    bad_login = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "WrongPass!234"},
    )
    assert bad_login.status_code == 401
    assert bad_login.json()["error"]["code"] == "invalid_credentials"


@pytest.mark.asyncio
async def test_refresh_rotation_and_reuse_detection(client):
    await signup_user(client)

    login_response = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": PASSWORD},
    )
    assert login_response.status_code == 200
    first_refresh = login_response.cookies.get(settings.refresh_cookie_name)
    assert first_refresh

    refresh_response = await client.post("/auth/refresh")
    assert refresh_response.status_code == 200
    rotated_refresh = refresh_response.cookies.get(settings.refresh_cookie_name)
    assert rotated_refresh and rotated_refresh != first_refresh

    client.cookies.pop(settings.refresh_cookie_name, None)
    client.cookies.set(
        settings.refresh_cookie_name,
        first_refresh,
        path=settings.refresh_cookie_path,
    )
    reuse_attempt = await client.post("/auth/refresh")
    assert reuse_attempt.status_code == 401
    assert reuse_attempt.json()["error"]["code"] == "refresh_token_reused"

    client.cookies.pop(settings.refresh_cookie_name, None)
    client.cookies.set(
        settings.refresh_cookie_name,
        rotated_refresh,
        path=settings.refresh_cookie_path,
    )
    logout_response = await client.post("/auth/logout")
    assert logout_response.status_code == 200

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(RefreshToken))
        tokens = result.scalars().all()
        assert tokens
        assert all(token.revoked_at is not None for token in tokens)


@pytest.mark.asyncio
async def test_google_login_sets_context_cookie(client):
    response = await client.get("/auth/google/login")
    assert response.status_code == 302
    assert response.headers["location"].startswith("https://accounts.google.com")
    assert "google_oauth_ctx" in response.cookies
