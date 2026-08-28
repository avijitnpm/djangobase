import uuid

from django.conf import settings
from django.db import models


class ExternalIdentity(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    provider = models.CharField(max_length=32, default="kinde")
    external_id = models.CharField(max_length=255)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="external_identities")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "identity_externalidentity"
        constraints = [
            models.UniqueConstraint(fields=["provider", "external_id"], name="unique_provider_external_id"),
        ]

    def __str__(self):
        return f"{self.provider}:{self.external_id} -> {self.user_id}"
