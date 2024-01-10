from django.contrib import admin
from . import models
# Register your models here.
admin.site.register(models.UserServerKeys)
admin.site.register(models.PWcheck)