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

    for manager in (accounts, sessions, registrations, logins, profiles, yggdrasil):
        manager.add_routes(app)
    return app
