from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):

    ROLE_CHOICES = (
        ('admin', 'Administrator'),
        ('analyst', 'Security Analyst'),
        ('viewer', 'Viewer'),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='viewer')

    def __str__(self):
        return self.user.username