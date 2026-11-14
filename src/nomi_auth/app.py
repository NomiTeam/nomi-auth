"""
Create the application and connect its account services to HTTP routes.
"""

from fastapi import FastAPI

from .accounts import AccountManager
from .config import Settings
from .db import Database
from .logins import LoginManager
from .profiles import ProfileManager
from .receipts import ReceiptManager
from .registrations import RegistrationManager
from .runtime import Runtime
from .sessions import SessionManager
from .yggdrasil import Yggdrasil


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    database = Database.from_settings(settings)
    runtime = Runtime(database)
    app = FastAPI(
        title="Nomi Auth",
        version="0.1.0",
        lifespan=runtime.lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.db = database
    app.state.settings = settings
    app.middleware("http")(runtime.guard)
    runtime.install_error_handlers(app)

    # Share the same managers so protocol routes use the same account rules.
    accounts = AccountManager(settings, database)
    receipts = ReceiptManager(settings, database)
    sessions = SessionManager(settings, database, accounts)
    registrations = RegistrationManager(settings, database, accounts, sessions)
    logins = LoginManager(settings, database, accounts, receipts, sessions)
    profiles = ProfileManager(settings, database, accounts, receipts)
    yggdrasil = Yggdrasil(settings, database, accounts)

    app.get("/health", response_model=None)(accounts.health)
    app.get("/api/v1/names/availability", response_model=None)(accounts.availability)
    app.get("/api/v1/game/profile", response_model=None)(sessions.current_profile)
    app.post("/api/v1/sessions/refresh", response_model=None)(sessions.refresh)
    app.delete("/api/v1/sessions/refresh", status_code=204, response_model=None)(sessions.revoke)
    app.delete("/api/v1/sessions/current", status_code=204, response_model=None)(sessions.logout)
    app.get("/api/v1/me", response_model=None)(sessions.me)
    app.post("/api/v1/registrations", status_code=201, response_model=None)(registrations.start)
    app.get("/api/v1/registrations/{request_id}", response_model=None)(registrations.status)
    app.delete("/api/v1/registrations/{request_id}", response_model=None)(registrations.cancel)
    app.post("/internal/v1/registrations/redeem", response_model=None)(registrations.redeem)
    app.post("/api/v1/registrations/{request_id}/session", response_model=None)(registrations.exchange)
    app.post("/api/v1/logins", status_code=201, response_model=None)(logins.start)
    app.get("/api/v1/logins/{request_id}", response_model=None)(logins.status)
    app.delete("/api/v1/logins/{request_id}", response_model=None)(logins.cancel)
    app.post("/internal/v1/logins/verify", response_model=None)(logins.verify)
    app.post("/internal/v1/logins/register", response_model=None)(logins.register)
    app.post("/api/v1/logins/{request_id}/session", response_model=None)(logins.exchange)
    app.patch("/api/v1/me/profile/name", response_model=None)(profiles.rename)
    app.patch("/api/v1/game/profiles/{profile_id}/name", response_model=None)(profiles.rename_game)
    app.post("/internal/v1/profiles/rename", response_model=None)(profiles.rename_member)
    app.put("/api/v1/me/profile/skin", response_model=None)(profiles.upload_skin)
    app.put("/api/yggdrasil/api/user/profile/{profile_id}/skin", status_code=204, response_model=None)(
        profiles.upload_game_skin
    )
    app.delete("/api/v1/me/profile/skin", status_code=204, response_model=None)(profiles.clear_skin)
    app.get("/textures/{texture_hash}", response_model=None)(profiles.texture)
    app.get("/api/yggdrasil" + "/", response_model=None)(yggdrasil.metadata)
    app.get("/api/yggdrasil", response_model=None)(yggdrasil.metadata)
    app.post("/api/yggdrasil" + "/authserver/authenticate", response_model=None)(
        yggdrasil.legacy_auth_disabled
    )
    app.post("/api/yggdrasil" + "/authserver/signout", response_model=None)(yggdrasil.legacy_auth_disabled)
    app.post("/api/yggdrasil" + "/authserver/refresh", response_model=None)(yggdrasil.game_refresh)
    app.post("/api/yggdrasil" + "/authserver/validate", status_code=204, response_model=None)(
        yggdrasil.game_validate
    )
    app.post("/api/yggdrasil" + "/authserver/invalidate", status_code=204, response_model=None)(
        yggdrasil.game_invalidate
    )
    app.post(
        "/api/yggdrasil" + "/sessionserver/session/minecraft/join", status_code=204, response_model=None
    )(yggdrasil.join)
    app.get("/api/yggdrasil" + "/sessionserver/session/minecraft/hasJoined", response_model=None)(
        yggdrasil.has_joined
    )
    app.get("/api/yggdrasil" + "/sessionserver/session/minecraft/profile/{profile_id}", response_model=None)(
        yggdrasil.get_profile
    )
    app.post("/api/yggdrasil" + "/api/profiles/minecraft", response_model=None)(yggdrasil.profiles)
    return app
