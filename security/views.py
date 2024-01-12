from django.shortcuts import render
from django.shortcuts import redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from pwmanager.models import Encryption
from .models import PWcheck
import bcrypt
from Crypto.Cipher import AES
def passwordreset(request):
    if request.method != "POST":
        return render(request, "pwreset.html")
    else:
        user = request.POST.get('Username')
        user2 = User.objects.get(Username=user)
        ekey = Encryption.objects.get(Owner=user2)
        pwcheck = PWcheck.objects.get(Owner=user2)
        pin = bytes(request.POST.get('pin'), 'UTF-8')
        salt = bytes(ekey.Salt, 'UTF-8')
        iv = eval(bytes(ekey.IV, 'UTF-8'))
        encryption_key = bcrypt.kdf(pin, salt, rounds=500,  desired_key_bytes=32)
        keys = AES.new(encryption_key, AES.MODE_CBC, iv)
        answer = pwcheck.Answer
        data = eval(pwcheck.Data)
        datade = keys.decrypt(data)
        padding_length = datade[-1]
        plaintext_bytes = datade[:-padding_length]
        datade = str(plaintext_bytes, 'UTF-8')
        if datade != answer:
            return render(request, "pwreset.html", {'msg': "wrong pin"})
        else:
            newpw = request.POST.get('newpw')
            user2.set_password(newpw)
    return render(request, 'complete.html')


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

