"""Adapter manifest model, registry and runners (spec 005)."""

from .manifest import AdapterManifest
from .registry import get_manifest, known_adapters
from .runner import DockerRunner, EchoRunner, build_run_request, get_runner

__all__ = [
    "AdapterManifest",
    "get_manifest",
    "known_adapters",
    "EchoRunner",
    "DockerRunner",
    "build_run_request",
    "get_runner",
]
