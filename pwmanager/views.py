from django.shortcuts import render
import secrets
import bcrypt, crypt, Crypto
from django.contrib.auth.models import User
#from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from django.contrib.auth.decorators import login_required
from .models import PW, Encryption
from django.shortcuts import redirect
import os
from security import crypto
# Create your views here.
n = 9999999999
@login_required
def setup(request):
    if request.method == "POST":
        ekey = Encryption()
        password = bytes(request.POST.get('pin'), 'UTF-8')
        if len(password) >= 6:
            salt = os.urandom(16)
            iv = os.urandom(16)
            ekey.Owner = request.user
            ekey.IV = iv
            ekey.Salt = salt
            ekey.save()
        else:
            return redirect('passwords/error')
        return redirect('/')
    else:
        return render(request, "test.html")
@login_required
def deleteAccount(request):
    if request.method == 'POST':
        ekey = Encryption.objects.get(Owner=request.user)
        ekey.delete()
        user = User.objects.get(username=request.user)
        user.delete()
        return redirect('/')
    else:
        return render(request, 'accountd.html')
    
@login_required
def add(request):
    if request.method == "POST":
        ekey = Encryption.objects.get(Owner=request.user)
        user_id = ekey.Owner_ID
        s = PW()
        salt = bytes(ekey.Salt, 'UTF-8')
        iv = bytes(ekey.IV, 'UTF-8')
        print(iv)
        print(len(iv))
        iv2 = eval(iv)
        print(iv2)
        iv = iv2
        pin = bytes(request.POST.get('pin'),'UTF-8')
        encryption_key = bcrypt.kdf(pin, salt, rounds=500,  desired_key_bytes=32)
        user = request.POST['username']
        pw = request.POST['Password']
        newPassword = crypto.encrypt(pw, encryption_key, request.user, iv)
        pw = newPassword
        TOTP = request.POST['TOTP']
        if TOTP == "":
            T2 = ""
            newTOTP = T2
        else:      
            T2 = bytes(TOTP, 'UTF-8')
            paddingTOTP = 16 - (len(TOTP) % 16)
# Apply PKCS7 padding to TOTP
            padded_TOTP = T2 + bytes([paddingTOTP]) * paddingTOTP
# Encrypt the padded_TOTP using the 'keys' AES cipher
            newTOTP = crypto.encrypt(padded_TOTP, encryption_key, request.user, iv)
            TOTP = newTOTP
        Date = request.POST['date']
        Owner = request.user
        s.Username = user
        s.Password = newPassword
        s.TOTP = newTOTP
        s.Date_Created = Date
        s.Owner = Owner
        s.Id = user_id
        s.save()
        return redirect('/')
