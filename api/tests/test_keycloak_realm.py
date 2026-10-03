"""The Keycloak realm files in deploy/keycloak: the ready-made ones import as they are, and stay in
sync with the template. Keycloak refuses the unrendered template ("Root URL is not a valid URL"),
which is why the ready-made files exist."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

KEYCLOAK = pathlib.Path(__file__).resolve().parents[2] / "deploy" / "keycloak"


def _load_render():
    spec = importlib.util.spec_from_file_location("khandaq_realm_render", KEYCLOAK / "render.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_ready_made_files_match_the_template():
    render = _load_render()
    assert set(render.ENVIRONMENTS) == {
        "khandaq-realm-staging.json",
        "khandaq-realm-production.json",
    }
    for name, url in render.ENVIRONMENTS.items():
        committed = (KEYCLOAK / name).read_text()
        assert committed == render.render(url), (
            f"{name} is stale: run python3 deploy/keycloak/render.py --all"
        )


@pytest.mark.parametrize(
    "name, origin",
    [
        ("khandaq-realm-staging.json", "https://khandaq-stg.siralabs.org"),
        ("khandaq-realm-production.json", "https://khandaq.siralabs.org"),
    ],
)
def test_a_ready_made_file_is_importable_and_secret_free(name, origin):
    text = (KEYCLOAK / name).read_text()
    assert "__PUBLIC_URL__" not in text
    realm = json.loads(text)
    assert realm["realm"] == "khandaq"
    assert realm["browserFlow"] == "khandaq browser"
    (client,) = [c for c in realm["clients"] if c["clientId"] == "khandaq-api"]
    assert client["rootUrl"] == origin
    assert client["redirectUris"] == [f"{origin}/api/auth/callback"]
    assert client["attributes"]["backchannel.logout.url"] == (
        f"{origin}/api/auth/backchannel-logout"
    )
    assert "secret" not in client  # Keycloak generates it at import; it is never in the file
    for idp in realm["identityProviders"]:
        assert idp["config"]["clientSecret"] == "set-in-admin-console"


@pytest.mark.parametrize(
    "url",
    [
        "khandaq.example.org",
        "ftp://khandaq.example.org",
        "https://khandaq.example.org/console",
        "https://user:pw@khandaq.example.org",
        "https://khandaq.example.org?x=1",
    ],
)
def test_render_refuses_anything_but_an_origin(url):
    with pytest.raises(ValueError):
        _load_render().render(url)


def test_render_normalises_a_trailing_slash():
    realm = json.loads(_load_render().render("https://khandaq.example.org/"))
    (client,) = [c for c in realm["clients"] if c["clientId"] == "khandaq-api"]
    assert client["redirectUris"] == ["https://khandaq.example.org/api/auth/callback"]
