from django.core.management.base import BaseCommand

from authorization.bootstrap import bootstrap_permissions, bootstrap_roles


class Command(BaseCommand):
    help = "Bootstrap platform permissions and roles"

    def handle(self, *args, **options):
        bootstrap_permissions()
        bootstrap_roles()
        self.stdout.write(self.style.SUCCESS("Platform permissions and roles bootstrapped"))
