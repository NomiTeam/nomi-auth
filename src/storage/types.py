from collections.abc import Iterator
from typing import Any, Protocol


class Cursor(Protocol):
    """
    The cursor operations used by account services, independent of SQL dialect.
    Row values are supplied by the selected database driver.
    """

    def fetchone(self) -> Any: ...
    def fetchall(self) -> list[Any]: ...
    def __iter__(self) -> Iterator[Any]: ...


class Connection(Protocol):
    """
    The shared DB-API operations required by a service transaction.
    """

    def execute(self, sql: str, parameters: tuple[Any, ...] = (), /) -> Cursor: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
    def close(self) -> None: ...
