from django.db import models
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth.models import User
from django.utils.timezone import *
import django
# Create your models here.
class PW(models.Model):
    Username = models.CharField(max_length=255, blank=True)
    Password = models.CharField(max_length=255, blank=True)
    URL = models.URLField(blank=True, default="https://google.com")
    TOTP = models.CharField(max_length=255, blank=True)
    Date_Created = models.DateField(default=django.utils.timezone.now)
    Owner = models.ForeignKey(User, on_delete=models.CASCADE)
    Notes = models.CharField(blank=True, max_length=500, default="empty") 

    def get_absolute_url(self):
        return reverse('edit', args=[self.id])
    def get_delete_url(self):
        return reverse('delete', args=[self.id])
class Encryption(models.Model):
   Owner = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
   Salt = models.CharField(max_length=500, default="0")
   IV = models.CharField(max_length=500, default="0")