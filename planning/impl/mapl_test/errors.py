"""Stable refusal codes shared across HTTP and pure components."""


class Refusal(Exception):
    def __init__(self, code, status=409):
        self.code = code
        self.status = status
        super().__init__(code)
