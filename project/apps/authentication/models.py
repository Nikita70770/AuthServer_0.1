from django.contrib.auth.models import AbstractUser
from django.db import models

# Create your models here.


class User(AbstractUser):
    email = models.EmailField(max_length=254, unique=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        verbose_name = 'User',
        verbose_name_plural = 'Users'

    def __str__(self):
        return f'<{self.id}> {self.username}'



# {
#     "email": "admin@gmail.com",
#     "password": "ZxcVBnm12345",
# }