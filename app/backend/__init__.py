from .base import Backend, ContainerNotFound, ServiceInfo
from .docker_backend import DockerBackend
from .mock_backend import MockBackend


def make_backend(kind: str) -> Backend:
    if kind == "mock":
        return MockBackend()
    if kind == "docker":
        return DockerBackend()
    raise ValueError(f"unknown backend: {kind}")


__all__ = ["Backend", "ContainerNotFound", "ServiceInfo", "make_backend", "DockerBackend", "MockBackend"]
