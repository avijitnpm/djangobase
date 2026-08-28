from typing import Optional
import uuid

from identity.models import ExternalIdentity


def resolve_user_id(provider: str, external_id: str) -> Optional[uuid.UUID]:
    try:
        return ExternalIdentity.objects.get(provider=provider, external_id=external_id).user_id
    except ExternalIdentity.DoesNotExist:
        return None
