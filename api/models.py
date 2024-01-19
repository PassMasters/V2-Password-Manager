from django.db import models
from django.contrib.auth.models import User
# Create your models here.
class AcessRequest(models.Model):
    code = models.CharField(max_length=255, primary_key=True)
    key  = models.CharField(max_length=255)
    Serial = models.CharField(max_length=255, default='0000')
    perm1 = models.CharField(max_length=1024, default='NONE')
    perm2 = models.CharField(max_length=1024, default='NONE')
    perm3 = models.CharField(max_length=1024, default='NONE')
    perm4 = models.CharField(max_length=1024, default='NONE')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    aproval = models.BooleanField(default=False)
class ConfCode(models.Model):
    req = models.OneToOneField(AcessRequest, on_delete=models.CASCADE)
    code = models.CharField(max_length=255, primary_key=True)
    key = models.CharField(max_length=255, default='NONE')
class apikey(models.Model):
    name = models.CharField(max_length=100)
    key = models.CharField(max_length=255, primary_key=True)
    Type = models.CharField(max_length=100)
    Activations = models.IntegerField()
    Limit = models.IntegerField()

class RegDevice(models.Model):
    key = models.CharField(max_length=255)
    Serial = models.CharField(max_length=255, primary_key=True)
    
class LinkedUser(models.Model):
    Device = models.ForeignKey(RegDevice, on_delete=models.CASCADE)
    User = models.ForeignKey(User, on_delete=models.CASCADE)
    Key = models.CharField(max_length=255)
    premisions = models.ForeignKey(AcessRequest, on_delete=models.CASCADE)