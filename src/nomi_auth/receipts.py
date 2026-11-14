import json
from typing import Any

from .config import Settings
from .db import Database
from .errors import Problem
from .models import MemberOperation, Redemption
from .security import current_timestamp, digest


class ReceiptManager:
    """
    Keep bot event results so message retries remain idempotent.
    """

    def __init__(self, settings: Settings, database: Database) -> None:
        self.settings = settings
        self.database = database

    def find(self, connection: Any, request_data: Redemption | MemberOperation, operation: str) -> Any:
        """
        Return a saved operation result or reject a changed event payload.
        """
        receipt = connection.execute(
            "SELECT * FROM receipts WHERE app_id=? AND event_id=? AND operation=?",
            (request_data.bot_app_id, request_data.event_id, operation),
        ).fetchone()
        if receipt:
            if receipt["payload_hash"] != digest(request_data.model_dump_json()):
                raise Problem("EVENT_CONFLICT", "事件参数与原请求不一致", 409)
            return json.loads(receipt["result"])
        return None

    def save(
        self,
        connection: Any,
        request_data: Redemption | MemberOperation,
        operation: str,
        result: dict[str, Any],
    ) -> None:
        """
        Remember the result so the same bot event cannot execute twice.
        """
        connection.execute(
            "INSERT INTO receipts VALUES(?,?,?,?,?,?)",
            (
                request_data.bot_app_id,
                request_data.event_id,
                operation,
                digest(request_data.model_dump_json()),
                json.dumps(result),
                current_timestamp(),
            ),
        )
