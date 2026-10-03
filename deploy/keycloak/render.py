#!/usr/bin/env python3
"""Fill in an install's public URL in the realm template before importing it into Keycloak.

    python3 deploy/keycloak/render.py https://khandaq-stg.siralabs.org > khandaq-realm.json
    python3 deploy/keycloak/render.py --all   # rewrite the ready-made staging/production files

The template itself cannot be imported: Keycloak refuses its `__PUBLIC_URL__` placeholder
("Root URL is not a valid URL", shown in the admin console as "unknown_error"). The ready-made
files next to it are rendered for the two environments and import as they are; a test keeps them
in sync with the template.

The output carries no secrets: the Google and GitHub client secrets and the `khandaq-api` client
secret are set in the admin console after the import (deploy/caprover.md §5).
"""

import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).parent
TEMPLATE = HERE / "khandaq-realm.template.json"

# The ready-made, importable files: one per environment, named by the origin they are rendered for.
ENVIRONMENTS = {
    "khandaq-realm-staging.json": "https://khandaq-stg.siralabs.org",
    "khandaq-realm-production.json": "https://khandaq.siralabs.org",
}


def render(public_url: str) -> str:
    """The realm JSON with `__PUBLIC_URL__` replaced; the URL must be an origin without a path."""
    parts = urlsplit(public_url)
    if (
        parts.scheme not in ("https", "http")
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise ValueError(f"expected an origin such as https://khandaq.example.org, got {public_url!r}")
    port = parts.port  # raises ValueError on an invalid port
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    origin = f"{parts.scheme}://{host}" + (f":{port}" if port else "")
    text = TEMPLATE.read_text().replace("__PUBLIC_URL__", origin)
    json.loads(text)  # still valid JSON
    return text


def write_all() -> None:
    """Rewrite the ready-made files from the template."""
    for name, url in ENVIRONMENTS.items():
        (HERE / name).write_text(render(url))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: render.py <public url> | --all")
    if sys.argv[1] == "--all":
        write_all()
        sys.exit(0)
    try:
        sys.stdout.write(render(sys.argv[1]))
    except ValueError as exc:
        sys.exit(str(exc))
