"""Thin wrapper over the docker CLI for the add-on containers Percy manages."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

PULL_TIMEOUT_SEC = 600
CMD_TIMEOUT_SEC = 60

Runner = Callable[..., subprocess.CompletedProcess]


class DockerError(RuntimeError):
    pass


@dataclass(frozen=True)
class ContainerSpec:
    key: str
    name: str
    image: str
    title: str
    description: str
    run_args: tuple[str, ...]
    web_url: str | None = None
    data_dirs: tuple[str, ...] = field(default_factory=tuple)

    def run_command(self) -> list[str]:
        return ["docker", "run", "-d", "--name", self.name, "--restart", "unless-stopped",
                "--label", "managed-by=percy", *self.run_args, self.image]


class Docker:
    def __init__(self, runner: Runner = subprocess.run) -> None:
        self._run_proc = runner

    def _run(self, args: Sequence[str], timeout: int = CMD_TIMEOUT_SEC) -> str:
        try:
            done = self._run_proc(list(args), capture_output=True, text=True, timeout=timeout, check=False)
        except FileNotFoundError as exc:
            raise DockerError("Docker is not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise DockerError(f"'{' '.join(args[:3])}' timed out") from exc
        if done.returncode != 0:
            raise DockerError((done.stderr or done.stdout or "docker failed").strip())
        return done.stdout.strip()

    def available(self) -> bool:
        try:
            self._run(["docker", "info", "--format", "{{.ServerVersion}}"])
            return True
        except DockerError:
            return False

    def state(self, name: str) -> str:
        """'running', 'exited', 'restarting', ... or 'missing'."""
        try:
            return self._run(["docker", "inspect", "-f", "{{.State.Status}}", name]) or "missing"
        except DockerError:
            return "missing"

    def install(self, spec: ContainerSpec) -> None:
        from percy.config import private_dir

        for directory in spec.data_dirs:  # AdGuard keeps its query log and password hash here
            private_dir(Path(directory))
        self._run(["docker", "pull", spec.image], timeout=PULL_TIMEOUT_SEC)
        if self.state(spec.name) != "missing":
            self._run(["docker", "rm", "-f", spec.name])
        self._run(spec.run_command())

    def start(self, name: str) -> None:
        self._run(["docker", "start", name])

    def stop(self, name: str) -> None:
        self._run(["docker", "stop", name])

    def remove(self, name: str) -> None:
        """Removes the container only; its data folder is kept."""
        self._run(["docker", "rm", "-f", name])

    def logs(self, name: str, lines: int = 50) -> str:
        return self._run(["docker", "logs", "--tail", str(lines), name])
