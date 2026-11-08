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

    def pull_image(self, image: str) -> str:
        img = self._client.images.pull(image)
        return img.tags[0] if img.tags else img.id

    def run_container(self, name, image, *, ports, env, volumes, privileged=False,
                      cap_add=(), sysctls=None, ulimits=None, restart_always=True):
        from docker.types import Ulimit
        self._client.containers.run(
            image, name=name, detach=True,
            # No container logging, same as the official client (--log-driver none).
            log_config=docker.types.LogConfig(type="none"),
            restart_policy={"Name": "always"} if restart_always else {},
            ports={k: v for k, v in ports.items()}, environment=env, volumes=volumes,
            privileged=privileged, cap_add=list(cap_add), sysctls=sysctls or {},
            ulimits=[Ulimit(name="nofile", soft=65536, hard=65536)] if ulimits else None)

    def remove_container(self, name: str, remove_volumes: bool = False) -> None:
        try:
            c = self._get(name)
        except ContainerNotFound:
            return
        c.remove(force=True, v=remove_volumes)

    def ensure_network(self, name: str, subnet: str) -> None:
        try:
            self._client.networks.get(name)
        except docker.errors.NotFound:
            pool = docker.types.IPAMPool(subnet=subnet)
            self._client.networks.create(name, driver="bridge",
                                         ipam=docker.types.IPAMConfig(pool_configs=[pool]))

    def connect_network(self, network: str, container: str, ip: str = "") -> None:
        net = self._client.networks.get(network)
        try:
            net.connect(container, ipv4_address=ip or None)
        except docker.errors.APIError as exc:
            if "already exists" not in str(exc):
                raise

    def build_image(self, tag: str, dockerfile_text: str) -> None:
        import io
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            data = dockerfile_text.encode()
            info = tarfile.TarInfo("Dockerfile")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        buf.seek(0)
        self._client.images.build(fileobj=buf, custom_context=True, tag=tag, rm=True)

    def image_exists(self, image: str) -> bool:
        try:
            self._client.images.get(image)
            return True
        except docker.errors.ImageNotFound:
            return False

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
