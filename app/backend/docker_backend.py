"""Real backend: talks to the local Docker daemon."""
from __future__ import annotations

import docker

from .base import ContainerNotFound, ServiceInfo


class DockerBackend:
    def __init__(self) -> None:
        self._client = docker.from_env()

    def _get(self, name: str):
        try:
            return self._client.containers.get(name)
        except docker.errors.NotFound:
            raise ContainerNotFound(name)

    def list_services(self) -> list[ServiceInfo]:
        out = []
        for c in self._client.containers.list(all=True):
            if not c.name.startswith("amnezia"):
                continue
            started = ""
            if c.status == "running":
                started = c.attrs.get("State", {}).get("StartedAt", "")
            ports = ", ".join(
                f"{k}->{v[0]['HostPort']}" for k, v in (c.ports or {}).items() if v
            )
            out.append(ServiceInfo(
                name=c.name, status=c.status, image=c.image.tags[0] if c.image.tags else c.image.short_id,
                started_at=started, ports=ports,
            ))
        out.sort(key=lambda s: s.name)
        return out

    def exec(self, container: str, cmd: list[str]) -> tuple[int, str]:
        c = self._get(container)
        code, output = c.exec_run(cmd, demux=False)
        return code, (output or b"").decode("utf-8", "replace")

    def restart(self, container: str) -> None:
        self._get(container).restart(timeout=10)

    def logs(self, container: str, tail: int = 200) -> str:
        c = self._get(container)
        return c.logs(tail=tail).decode("utf-8", "replace")

    def inspect(self, container: str) -> dict:
        c = self._get(container)
        env = {}
        for item in c.attrs.get("Config", {}).get("Env", []) or []:
            key, _, value = item.partition("=")
            env[key] = value
        ports = {}
        for guest, bindings in (c.attrs.get("NetworkSettings", {}).get("Ports", {}) or {}).items():
            if bindings:
                ports[guest] = bindings[0].get("HostPort", "")
        networks = {
            name: {"ip": net.get("IPAddress", "")}
            for name, net in (c.attrs.get("NetworkSettings", {}).get("Networks", {}) or {}).items()
        }
        return {"env": env, "ports": ports, "networks": networks}
