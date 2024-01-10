from django.contrib import admin
from .models import RegDevice, apikey, LinkedUser, AcessRequest, ConfCode
# Register your models here.

admin.site.register(RegDevice)
admin.site.register(apikey)
admin.site.register(LinkedUser)
admin.site.register(AcessRequest)
admin.site.register(ConfCode)