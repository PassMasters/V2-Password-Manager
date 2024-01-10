from django.shortcuts import render
from django.shortcuts import redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
def logon(request):
    if request.method != "POST":
        return render(request, "registration/login.html")
    else:
        username = request.POST['Username']
        password = request.POST['Password']
        user = authenticate(request,  username= username,
        password=password)
        if user is not None :
            login(request, user)
            return redirect ('/')
def signup1(request):
    if request.method != "POST":
        return render(request, "registration/signup.html")
    else:
        username = request.POST['Username']
        password = request.POST['Password']
        user = User.objects.create_user(
        username=  username,
        password=        password
    )
        user.save()
        user = authenticate(request,  username= username,
        password=password)
        if user is not None :
            login(request, user)
            return redirect ('/')