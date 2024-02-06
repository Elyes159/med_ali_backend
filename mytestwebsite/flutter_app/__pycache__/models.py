from django.db import models
from django.contrib.auth.models import AbstractUser, Group as DjangoGroup
from secure import PermissionsPolicy

# Create your models here.
class Product(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    price = models.CharField(max_length=10)

from django.db import models
from django.contrib.auth.models import AbstractUser, Group as DjangoGroup
from secure import PermissionsPolicy

class CustomUser(AbstractUser):
    groups = models.ManyToManyField(DjangoGroup, related_name='customuser_set', blank=True)
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='customuser_set',  # Ajoutez ou changez le nom ici pour éviter le conflit
        blank=True
    )

