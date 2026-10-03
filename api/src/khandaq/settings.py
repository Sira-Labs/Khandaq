"""Runtime configuration, from environment variables only (no secrets in code; ADR-0006).

In production the app fails closed: it refuses to start on missing or placeholder secrets. This is
the bootable R1 skeleton — only the settings the current endpoints need are enforced here; OIDC and
the full scope/evidence settings are enforced as their specs land (008, 004).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

from .evidence_crypto import MIN_KEY_CHARS
from .evidence_store import parse_store_url

# Values that must never reach production: the examples shipped in deploy/.env.example.
_PLACEHOLDERS = {
    "",
    "changeme",
    "generate-with-openssl-rand-base64-48",
    "generate-with-openssl-rand-base64-32",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KHANDAQ_", extra="ignore")

    # Strict on purpose: anything other than prod enables the dev login stub, so a typo such as
    # "production" must stop the app from starting rather than silently open it.
    env: Literal["dev", "test", "prod"] = "dev"
    role: str = "api"  # api | worker
    public_url: str = ""

    # Secrets / connections (enforced in prod by validate_runtime()).
    session_secret: str = ""
    database_url: str = ""
    migration_database_url: str = ""  # owner login for migrations; falls back to database_url
    # Evidence envelope key (ADR-0016): any string of at least 32 characters; the KEK is derived
    # from it. Retired keys (comma-separated) still decrypt the objects written under them.
    evidence_key: str = ""
    evidence_previous_keys: str = ""

    # Object store for evidence (spec 014): s3://<bucket>[/<prefix>]; empty = evidence_dir.
    object_store_url: str = ""
    object_store_endpoint: str = ""
    object_store_region: str = "us-east-1"
    object_store_access_key_id: str = ""
    object_store_secret_access_key: str = ""

    # Identity (OIDC BFF; spec 008 / ADR-0005). Required in prod (see validate_runtime).
    oidc_issuer: str = ""
    oidc_client_id: str = "khandaq-api"
    oidc_client_secret: str = ""
    session_ttl_hours: int = 12
    admin_email: str = ""
    # Who may sign in besides admin_email: comma-separated addresses. The realm brokers any Google
    # or GitHub account, so without this list anyone could sign in and start runs.
    # Empty = admin only.
    allowed_emails: str = ""

    @property
    def oidc_configured(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_secret and self.public_url)

    def email_allowed(self, email: str) -> bool:
        """True if the address is admin_email or on KHANDAQ_ALLOWED_EMAILS (case-insensitive)."""
        allowed = {e.strip().lower() for e in self.allowed_emails.split(",") if e.strip()}
        if self.admin_email.strip():
            allowed.add(self.admin_email.strip().lower())
        return email.strip().lower() in allowed

    sigstore: str = "off"
    adapter_runtime: str = "docker-socket"
    adapter_registry: str = "ghcr.io/sira-labs"
    # Container runs (spec 012, ADR-0009). The forwarder runs from an image with Python 3 — the
    # deployment's own API image; without it, container runs are refused.
    forwarder_image: str = ""
    adapter_egress_network: str = "bridge"  # the Docker network targets are reachable from
    adapter_timeout_seconds: int = 3600
    adapter_output_limit_mb: int = 256
    # Where container runs' evidence bytes are retained, encrypted and write-once, when no object
    # store is configured (specs 012, 014). The worker needs this volume.
    evidence_dir: str = "/var/lib/khandaq/evidence"
    worker_poll_seconds: float = 5.0
    # Campaigns (spec 016, ADR-0017): the shortest interval a campaign may re-run at, so a
    # schedule cannot hammer a client system. Rules of engagement still apply per run.
    campaign_min_interval_minutes: int = 60

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    def validate_runtime(self) -> None:
        """Fail closed in production on missing/placeholder settings the app relies on today.

        Kept deliberately narrow for the bootable skeleton: a placeholder session secret or a
        missing database URL must stop prod from starting. Further requirements (OIDC, evidence
        key) are added here as their specs are implemented, so prod never silently runs insecure.
        """
        if not self.is_prod:
            return
        problems: list[str] = []
        if self.session_secret in _PLACEHOLDERS:
            problems.append("KHANDAQ_SESSION_SECRET must be set to a real value")
        if not self.database_url:
            problems.append("KHANDAQ_DATABASE_URL must be set")
        if self.evidence_key in _PLACEHOLDERS:
            problems.append("KHANDAQ_EVIDENCE_KEY must be set to a real value")
        elif len(self.evidence_key) < MIN_KEY_CHARS:
            problems.append(f"KHANDAQ_EVIDENCE_KEY must be at least {MIN_KEY_CHARS} characters")
        retired = [k.strip() for k in self.evidence_previous_keys.split(",") if k.strip()]
        if any(len(k) < MIN_KEY_CHARS for k in retired):
            problems.append(
                "KHANDAQ_EVIDENCE_PREVIOUS_KEYS entries must be at least "
                f"{MIN_KEY_CHARS} characters"
            )
        try:
            parse_store_url(self.object_store_url)
        except ValueError as exc:
            problems.append(str(exc))
        # OIDC BFF is the only authentication path in prod (the dev stub refuses there); without it
        # no one could log in, so the API fails closed (spec 008 / ADR-0005). Only the api role
        # serves logins: the worker never sees a browser, so it is not given (and must not need)
        # the client secret — least privilege.
        if self.role == "api":
            if not self.oidc_issuer:
                problems.append("KHANDAQ_OIDC_ISSUER must be set")
            if self.oidc_client_secret in _PLACEHOLDERS:
                problems.append("KHANDAQ_OIDC_CLIENT_SECRET must be set to a real value")
            if not self.public_url:
                problems.append("KHANDAQ_PUBLIC_URL must be set (OIDC redirect URI)")
        if problems:
            raise RuntimeError(
                "Refusing to start in prod with insecure configuration: " + "; ".join(problems)
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
