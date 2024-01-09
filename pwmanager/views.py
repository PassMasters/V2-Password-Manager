from django.shortcuts import render
import secrets
import bcrypt, Crypto #crypt, Crypto
from django.contrib.auth.models import User
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from django.contrib.auth.decorators import login_required
from .models import PW, Encryption
from django.shortcuts import redirect
import os
import pyotp
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
        return render(request, "pin.html")
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
    else: 
        return render(request, 'add.html')
@login_required
def homepage(request):
    if request.method == 'POST':
        
        passwordss = PW.objects.filter(Owner=request.user).values('Username', 'Password', 'TOTP', 'pk', 'Notes', 'URL')


        
        ekey = Encryption.objects.get(Owner=request.user)
        salt = bytes(ekey.Salt,'UTF-8')
        iv = eval(bytes(ekey.IV, 'UTF-8'))

        pin = bytes(request.POST.get('pin'), 'UTF-8')
        encryption_key = bcrypt.kdf(pin, salt,rounds=500,  desired_key_bytes=32)
 
        mainlist = []
        pwlist = list(passwordss)
        runs = 0
        try:
            for i in range(len(pwlist)):
                y1 = dict(pwlist[i])
                print(y1)
                y2 = y1['Username']
                runs  = runs + 1
                y3 = eval(bytes(y1['Password'], 'UTF-8'))
                keys = AES.new(encryption_key, AES.MODE_CBC, iv)
                try:
                    y6 = crypto.d2(y3, keys)
                except  Exception as e:
                    if runs == 1:
                        print("wrong pin")
                        return render(request, "pin.html", {'msg': str(e, 'UTF-8')})
                    else:
                        print("error")
                        return render(request, "error.html", {'msg': str(e, 'UTF-8')})
                x5 = y1['TOTP']
                if x5 == "":
                    totpcalc = "N/A"
                else:
                    x6 = eval(bytes(x5, 'UTF-8'))
                    x8 = keys.decrypt(x6)
                    padding_length2 = x8[-1]
                    plaintext_bytes2 = x8[:-padding_length2]
                    x7 = str(plaintext_bytes2, 'UTF-8')
                    try:
                        totp = pyotp.TOTP(x7)
                        totpcalc = totp.now()
                    except Exception as e:
                        totpcalc = "improper TOTP secret please edit your TOTP"
               
                
                pk = y1['pk']
                z2 = PW.objects.get(pk=pk)
                pw_url= z2.get_absolute_url()
                notes1 = y1['Notes']
                url1 = y1['URL']
                data_dict = {
                "Username": y2,
                "Password": y6,
                "TOTP": totpcalc,
                "URL" : url1,
                "notes" : notes1,
                "EditURL": pw_url
            }
                mainlist.append(data_dict)
            return render (request, 'pw_homepage.html', {'pwlist': mainlist})
        except Exception as e:
            msg ="an error has occured decypting passwords"
            return render(request, 'error.html', {'msg': str(e, 'UTF-8') })
    else:
         return render(request, 'pin.html')