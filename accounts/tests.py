import uuid

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase

from accounts.models import Organization, OrganizationMembership


class IdentityTests(TestCase):
    def test_user_can_be_created(self):
        User = get_user_model()
        user = User.objects.create_user(username="alice", password="testpass123")
        self.assertIsNotNone(user.pk)

    def test_user_ids_are_uuids(self):
        User = get_user_model()
        user = User.objects.create_user(username="bob", password="testpass123")
        self.assertIsInstance(user.id, uuid.UUID)

    def test_two_users_receive_different_uuids(self):
        User = get_user_model()
        u1 = User.objects.create_user(username="u1", password="testpass123")
        u2 = User.objects.create_user(username="u2", password="testpass123")
        self.assertNotEqual(u1.id, u2.id)

    def test_organization_receives_uuid(self):
        org = Organization.objects.create(name="Acme")
        self.assertIsInstance(org.id, uuid.UUID)

    def test_membership_links_correct_user_and_organization(self):
        User = get_user_model()
        user = User.objects.create_user(username="carol", password="testpass123")
        org = Organization.objects.create(name="Org1")
        membership = OrganizationMembership.objects.create(user=user, organization=org)
        self.assertEqual(membership.user_id, user.id)
        self.assertEqual(membership.organization_id, org.id)

    def test_duplicate_memberships_are_rejected(self):
        User = get_user_model()
        user = User.objects.create_user(username="dave", password="testpass123")
        org = Organization.objects.create(name="Org2")
        OrganizationMembership.objects.create(user=user, organization=org)
        with self.assertRaises(IntegrityError):
            OrganizationMembership.objects.create(user=user, organization=org)
