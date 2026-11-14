import asyncio
import logging
import sqlite3
import threading
import time
import uuid
from collections import defaultdict, deque
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress

import pymysql
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response

from .db import Database
from .errors import Problem


class Runtime:
    """
    Own request limits and background cleanup for one application instance.
    """

    def __init__(self, database: Database) -> None:
        self.database = database
        self.requests: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self.request_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(self, app: FastAPI) -> AsyncGenerator[None, None]:
        cleanup_task = asyncio.create_task(self._cleanup())
        try:
            yield
        finally:
            cleanup_task.cancel()
            with suppress(asyncio.CancelledError):
                await cleanup_task

    async def _cleanup(self) -> None:
        from .maintenance import cleanup_textures

        next_texture_cleanup = 0
        while True:
            timestamp = int(time.time())
            try:
                await asyncio.to_thread(self.database.cleanup_if_due, timestamp)
                if timestamp >= next_texture_cleanup:
                    await asyncio.to_thread(cleanup_textures, self.database, timestamp)
                    next_texture_cleanup = timestamp + 3600
            except (sqlite3.Error, pymysql.MySQLError, OSError):
                logging.getLogger(__name__).exception("Transient data cleanup failed")
            await asyncio.sleep(30)

    async def guard(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if self._rate_limited(request):
            return JSONResponse(
                {"code": "RATE_LIMITED", "message": "请求过于频繁"}, 429
            )

        # Access-time cleanup also handles records that expired while stopped.
        try:
            await asyncio.to_thread(self.database.cleanup_if_due, int(time.time()))
        except (sqlite3.Error, pymysql.MySQLError):
            return database_unavailable()

        response = await call_next(request)
        if not request.url.path.startswith("/textures/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def _rate_limited(self, request: Request) -> bool:
        sensitive = request.method == "POST" and (
            request.url.path.startswith("/api/v1/")
            or request.url.path.endswith(("/authenticate", "/signout"))
        )
        source = request.client.host if request.client else "unknown"
        category = "sensitive" if sensitive else "general"
        limit = 20 if sensitive else 300
        timestamp = time.monotonic()

        # Use only the client address resolved by the configured trusted proxy.
        with self.request_lock:
            bucket = self.requests[(source, category)]
            while bucket and bucket[0] < timestamp - 60:
                bucket.popleft()
            if len(bucket) >= limit:
                return True
            bucket.append(timestamp)
            self._remove_stale_sources(timestamp)
        return False

    def _remove_stale_sources(self, timestamp: float) -> None:
        if len(self.requests) <= 10000:
            return
        stale_sources = []
        for source, timestamps in self.requests.items():
            if not timestamps or timestamps[-1] < timestamp - 60:
                stale_sources.append(source)
        for source in stale_sources:
            del self.requests[source]

    def install_error_handlers(self, app: FastAPI) -> None:
        app.add_exception_handler(Problem, handle_problem)
        app.add_exception_handler(sqlite3.OperationalError, handle_database_error)
        app.add_exception_handler(pymysql.MySQLError, handle_database_error)
        app.add_exception_handler(RequestValidationError, handle_invalid_request)


def database_unavailable() -> JSONResponse:
    return JSONResponse(
        {"code": "DATABASE_UNAVAILABLE", "message": "数据库暂时不可用，请重试"}, 503
    )


async def handle_problem(request: Request, error: Exception) -> JSONResponse:
    assert isinstance(error, Problem)
    if request.url.path.startswith("/api/yggdrasil"):
        return JSONResponse(
            {"error": "ForbiddenOperationException", "errorMessage": error.message},
            error.status,
        )
    return JSONResponse(
        {"code": error.code, "message": error.message, "request_id": uuid.uuid4().hex},
        error.status,
    )


async def handle_database_error(request: Request, error: Exception) -> JSONResponse:
    return database_unavailable()


async def handle_invalid_request(request: Request, error: Exception) -> JSONResponse:
    if request.url.path.startswith("/api/yggdrasil"):
        return JSONResponse(
            {"error": "IllegalArgumentException", "errorMessage": "Invalid request."},
            400,
        )
    # Validation inputs may contain credentials; never echo them back to clients.
    return JSONResponse(
        {"code": "INVALID_REQUEST", "message": "请求格式或参数不符合要求"}, 422
    )
