"""Runtime configuration, from environment variables only (no secrets in code; ADR-0006).

In production the app fails closed: it refuses to start on missing or placeholder secrets. This is
the bootable R1 skeleton — only the settings the current endpoints need are enforced here; OIDC and
the full scope/evidence settings are enforced as their specs land (008, 004).
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

# Values that must never reach production: the examples shipped in deploy/.env.example.
_PLACEHOLDERS = {
    "",
    "changeme",
    "generate-with-openssl-rand-base64-48",
    "generate-with-openssl-rand-base64-32",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KHANDAQ_", extra="ignore")

    env: str = "dev"  # dev | prod
    role: str = "api"  # api | worker
    public_url: str = ""

    # Secrets / connections (enforced in prod by validate_runtime()).
    session_secret: str = ""
    database_url: str = ""
    migration_database_url: str = ""  # owner login for migrations; falls back to database_url
    evidence_key: str = ""

    # Object store (evidence). Optional until the evidence path lands (spec 004).
    object_store_url: str = ""
    object_store_endpoint: str = ""

    # Identity (OIDC BFF; spec 008 / ADR-0005). Required in prod (see validate_runtime).
    oidc_issuer: str = ""
    oidc_client_id: str = "khandaq-api"
    oidc_client_secret: str = ""
    session_ttl_hours: int = 12
    admin_email: str = ""

    @property
    def oidc_configured(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_secret and self.public_url)

    sigstore: str = "off"
    adapter_runtime: str = "docker-socket"
    adapter_registry: str = "ghcr.io/sira-labs"

    @property
    def is_prod(self) -> bool:
        return self.env.lower() == "prod"

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
        # OIDC BFF is the only authentication path in prod (the dev stub refuses there); without it
        # no one could log in, so fail closed (spec 008 / ADR-0005).
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
