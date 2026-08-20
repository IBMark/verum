import os
from typing import List


class Service:
    def __init__(self, name: str) -> None:
        self.name = name

    @property
    def label(self) -> str:
        return f"{self.name}"


def main(argv: List[str]) -> int:
    return len(Service(argv[0]).label)
