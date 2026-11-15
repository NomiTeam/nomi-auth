"""
Create the application and connect its account services to HTTP routes.
"""

from fastapi import FastAPI

from src.core.config import Settings
from src.core.runtime import Runtime
from src.services.accounts import AccountManager
from src.services.logins import LoginManager
from src.services.profiles import ProfileManager
from src.services.receipts import ReceiptManager
from src.services.registrations import RegistrationManager
from src.services.sessions import SessionManager
from src.services.yggdrasil import Yggdrasil
from src.storage.database import Database


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
