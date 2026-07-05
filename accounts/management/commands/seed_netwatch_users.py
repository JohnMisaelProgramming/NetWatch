from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from accounts.models import Profile


class Command(BaseCommand):
    help = 'Seed NetWatch with one admin, one analyst, and one viewer account.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--password',
            default='NetWatch123!',
            help='Password assigned to all seeded users.',
        )

    def handle(self, *args, **options):
        password = options['password']
        seed_users = [
            {'username': 'admin', 'role': 'admin', 'email': 'admin@netwatch.local'},
            {'username': 'analyst', 'role': 'analyst', 'email': 'analyst@netwatch.local'},
            {'username': 'viewer', 'role': 'viewer', 'email': 'viewer@netwatch.local'},
        ]

        for seed in seed_users:
            user, created = User.objects.get_or_create(
                username=seed['username'],
                defaults={'email': seed['email']},
            )

            if created:
                user.set_password(password)
                user.is_staff = seed['role'] == 'admin'
                user.is_superuser = seed['role'] == 'admin'
                user.save()
                action = 'created'
            else:
                updated = False
                if user.email != seed['email']:
                    user.email = seed['email']
                    updated = True
                if user.check_password(password) is False:
                    user.set_password(password)
                    updated = True
                if seed['role'] == 'admin' and not user.is_staff:
                    user.is_staff = True
                    updated = True
                if seed['role'] == 'admin' and not user.is_superuser:
                    user.is_superuser = True
                    updated = True
                if updated:
                    user.save()
                action = 'updated'

            profile, _ = Profile.objects.get_or_create(user=user)
            profile.role = seed['role']
            profile.save()

            self.stdout.write(self.style.SUCCESS(f'{seed["username"]} {action} as {seed["role"]}'))

        self.stdout.write(self.style.SUCCESS('NetWatch seed users are ready.'))