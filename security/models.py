from django.db import models
from django.contrib.auth.models import User
# Create your models here.
class UserServerKeys(models.Model):
    Owner = models.ForeignKey(User, on_delete=models.CASCADE)
    key = models.CharField(max_length=1024, default="1")
    IV = models.CharField(max_length=1024, default="1")
class PWcheck(models.Model):
    Owner = models.ForeignKey(User, on_delete=models.CASCADE)
    Data = models.CharField(max_length=255)
    Answer = models.CharField(max_length=255)