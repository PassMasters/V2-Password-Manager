from django.shortcuts import render
from django.shortcuts import redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from pwmanager.models import Encryption
from .models import PWcheck
import bcrypt
from . import crypto
from Crypto.Cipher import AES
def passwordreset(request):
    if request.method != "POST":
        return render(request, "pwreset.html")
    else:
        user = request.POST.get('Username')
        user2 = User.objects.get(username=user)
        ekey = Encryption.objects.get(Owner=user2)
        pwcheck = PWcheck.objects.get(Owner=user2)
        pin = bytes(request.POST.get('pin'), 'UTF-8')
        salt = eval(bytes(ekey.Salt, 'UTF-8'))
        iv = eval(bytes(ekey.IV, 'UTF-8'))
        encryption_key = bcrypt.kdf(pin, salt, rounds=500,  desired_key_bytes=32)
        print(encryption_key)
        keys = AES.new(encryption_key, AES.MODE_CBC, iv)
        answer = pwcheck.Answer
        data = eval(bytes(pwcheck.Data, 'UTF-8'))
        try:
            datade = crypto.decrypt(data, keys)
            if datade == '':
                datade = keys.decrypt(data)
                padding_length = datade[-1]
                plaintext_bytes = datade[:-padding_length]
                datade = str(plaintext_bytes, 'UTF-8')
        except Exception:
            return render(request, "dead.html")
        if datade != answer:
            return render(request, "pwreset.html", {'msg': "wrong pin"})
        else:
            newpw = request.POST.get('newpw')
            user2.set_password(newpw)
            return render(request, 'complete.html')
def logout(request):
    user = request.user
    logout(request, user)

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
            next_url = request.GET.get('next', '/')
            return redirect(next_url)

        else: 
            context = {
                'error': "Invalid Username or Password"
                }
            return render(request, "registration/login.html", context)
def signup1(request):
    if request.method != "POST":
        return render(request, "registration/signup.html")
    else:
        username = request.POST['Username']
        password = request.POST['Password']
        try:
            user = User.objects.create_user(
        username=  username,
        password=        password
    )
        except Exception:
            context = {
                'error': "User Already Exsits"
                }
            return render(request, "registration/signup.html", context)
        user.save()
        user = authenticate(request,  username= username,
        password=password)
        if user is not None :
            login(request, user)
            next_url = request.GET.get('next', '/')
            return redirect(next_url)

