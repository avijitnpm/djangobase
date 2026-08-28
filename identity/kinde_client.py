from identity.config import KindeConfig, get_kinde_config
from identity.errors import KindeNotConfiguredError


def get_kinde_oauth(config: KindeConfig | None = None):
    from kinde_sdk.auth.oauth import OAuth

    cfg = config or get_kinde_config()
    if cfg is None:
        raise KindeNotConfiguredError("Kinde is not configured")
    return OAuth(
        client_id=cfg.client_id,
        client_secret=cfg.client_secret,
        host=cfg.host,
        redirect_uri=cfg.redirect_uri,
    )
