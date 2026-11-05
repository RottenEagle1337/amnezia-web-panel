"""Abstraction over "how the panel talks to Amnezia containers".

Two implementations:
- DockerBackend: real server, via /var/run/docker.sock
- MockBackend: in-memory fixtures for local development and tests
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class ServiceInfo:
    name: str
    status: str       # running | exited | ...
    image: str
    started_at: str   # raw string from docker, "" if not running
    ports: str


class Backend(Protocol):
    def list_services(self) -> list[ServiceInfo]: ...
    def exec(self, container: str, cmd: list[str]) -> tuple[int, str]: ...
    def restart(self, container: str) -> None: ...
    def logs(self, container: str, tail: int = 200) -> str: ...
    def inspect(self, container: str) -> dict:
        """Container metadata: {"env": {...}, "ports": {"443/tcp": "443"}, "networks": {...}}"""
        ...


class ContainerNotFound(Exception):
    pass
