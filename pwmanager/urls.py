from os import name
from django.urls import path,include
from . import views
from django.conf.urls.static import static
from django.views.generic import TemplateView
urlpatterns = [
    path('', views.startpage),
    path('destroyaccount', views.deleteAccount),
    path('add',  views.add),
    path('setup', views.setup),
    path('home', views.homepage)
]