class Problem(Exception):
    """
    A public error code and safe message, independent of the HTTP response format.
    """

    def __init__(self, code: str, message: str, status: int = 400) -> None:
        self.code = code
        self.message = message
        self.status = status
