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
    def inspect(self, container: str) -> dict:
        """Container metadata: {"env": {...}, "ports": {"443/tcp": "443"}, "networks": {...}}"""
        ...

    # Deployment operations (Phase C).
    def pull_image(self, image: str) -> str:
        """Pull an image; returns its tag or id. Raises RuntimeError on failure."""
        ...

    def run_container(self, name: str, image: str, *, ports: dict, env: dict,
                      volumes: dict, privileged: bool = False, cap_add=(),
                      sysctls: dict | None = None, ulimits=None,
                      restart_always: bool = True) -> None: ...

    def remove_container(self, name: str, remove_volumes: bool = False) -> None: ...

    def ensure_network(self, name: str, subnet: str) -> None: ...

    def connect_network(self, network: str, container: str, ip: str = "") -> None: ...

    def build_image(self, tag: str, dockerfile_text: str) -> None:
        """Build an image from an in-memory Dockerfile (tar stream context)."""
        ...

    def image_exists(self, image: str) -> bool: ...


class ContainerNotFound(Exception):
    pass
