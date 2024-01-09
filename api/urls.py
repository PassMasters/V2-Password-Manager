from os import name
from django.urls import path,include
from . import views
from django.conf.urls.static import static
from django.views.generic import TemplateView

urlpatterns = [
    path('apikey', views.obtain),
    path('aprove/<int:pk>', views.Aprove),
    path('request', views.acessrequestcode),
    path('deactivate', views.Deactveate),
    path('tokenrequest', views.TokenRequest)
]