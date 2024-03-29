"""
URL configuration for app project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from pwmanager.views import startpage as home
from security.views import logon as logon
from security.views import passwordreset as pwreset
from security.views import signup1 as signup
from security.views import logout_user as logout
urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include('api.urls')),
    path("passwords/", include('pwmanager.urls')),
    path("secure/", include('security.urls')),
    path("accounts/login/", logon),
    path('', home),
    path("accounts/signup/", signup),
    path("accounts/pwreset/", pwreset),
    path("accounts/logout/", logout)

]
