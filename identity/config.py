import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class KindeConfig:
    client_id: str
    client_secret: str
    host: str
    redirect_uri: str
    issuer_url: Optional[str] = None


def get_kinde_config() -> Optional[KindeConfig]:
    client_id = os.getenv("KINDE_CLIENT_ID", "").strip()
    client_secret = os.getenv("KINDE_CLIENT_SECRET", "").strip()
    host = os.getenv("KINDE_HOST", "").strip()
    redirect_uri = os.getenv("KINDE_REDIRECT_URI", "").strip()
    issuer_url = os.getenv("KINDE_ISSUER_URL", "").strip() or None
    if not client_id or not client_secret or not host or not redirect_uri:
        return None
    return KindeConfig(
        client_id=client_id,
        client_secret=client_secret,
        host=host,
        redirect_uri=redirect_uri,
        issuer_url=issuer_url,
    )


def is_kinde_configured() -> bool:
    return get_kinde_config() is not None
