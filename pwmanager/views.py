from django.shortcuts import render
import secrets
import bcrypt, Crypto #crypt, Crypto
from django.contrib.auth.models import User
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from .models import PW, Encryption
from security.models import PWcheck 
from .forms import PwEdit
from django.shortcuts import redirect, get_object_or_404
import os
import pyotp
from security import crypto
# Create your views here.
n = 9999999999

def startpage(request):
    return render(request, "startpage.html")

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
            encryption_key = bcrypt.kdf(password, salt, rounds=500,  desired_key_bytes=32)
            model = PWcheck()
            model.Owner = request.user
            word = bytes("munchyisverybadthisdecryptedwell", 'UTF-8')
            keys = AES.new(encryption_key, AES.MODE_CBC, iv)
            model.Data = crypto.encrypt2(word, keys)
            model.Answer = str(word, 'UTF-8')
            model.save()
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
        checkmodel = PWcheck.objects.get(Owner=request.user)
        answer = checkmodel.Answer
        data = eval(checkmodel.Data)
        pwmodel = PW()
        salt = eval(bytes(ekey.Salt, 'UTF-8'))
        iv = eval(bytes(ekey.IV, 'UTF-8'))
        pin = bytes(request.POST.get('pin'),'UTF-8')
        encryption_key = bcrypt.kdf(pin, salt, rounds=500,  desired_key_bytes=32)
        keys = AES.new(encryption_key, AES.MODE_CBC, iv)
        datade = keys.decrypt(data)
        padding_length = datade[-1]
        plaintext_bytes = datade[:-padding_length]
        datade = str(plaintext_bytes, 'UTF-8')
        if datade != answer:
            return render(request, "pin.html", {'msg': "wrong pin"})
        
        user = request.POST['username']
        pw = bytes(request.POST['Password'],'UTF-8')
        newPassword = crypto.encrypt(pw, encryption_key, request.user)
        pw = newPassword
        TOTP = request.POST['TOTP']
        if TOTP == "":
            T2 = ""
            newTOTP = T2
        else:      
            T2 = bytes(TOTP, 'UTF-8')
            newTOTP = crypto.encrypt(T2, encryption_key, request.user)
            TOTP = newTOTP
        Date = request.POST['date']
        pwmodel.Username = user
        pwmodel.Password = newPassword
        pwmodel.TOTP = newTOTP
        pwmodel.Date_Created = Date
        pwmodel.Owner = request.user
        pwmodel.save()
        return redirect('/')
    else: 
        return render(request, 'add.html')
@login_required
def homepage(request):
    if request.method == 'POST':
        
        passwordss = PW.objects.filter(Owner=request.user).values('Username', 'Password', 'TOTP', 'pk', 'Notes', 'URL')
        ekey = Encryption.objects.get(Owner=request.user)
        salt = eval(bytes(ekey.Salt,'UTF-8'))
        iv = eval(bytes(ekey.IV, 'UTF-8'))
        pin = bytes(request.POST.get('pin'), 'UTF-8')
        encryption_key = bcrypt.kdf(pin, salt,rounds=500,  desired_key_bytes=32)
        mainlist = []
        pwlist = list(passwordss)
        runs = 0
        for i in range(len(pwlist)):
                datadict = dict(pwlist[i])
                username = datadict['Username']
                runs  = runs + 1
                pwbytes = eval(bytes(datadict['Password'], 'UTF-8'))
                keys = AES.new(encryption_key, AES.MODE_CBC, iv)
                try:
                    password = crypto.decrypt(pwbytes, keys)
                except  Exception as e:
                    if runs == 1:
                        print("wrong pin")
                        return render(request, "pin.html", {'msg': str(e, 'UTF-8')})
                    else:
                        print("error")
                        return render(request, "error.html", {'msg': str(e, 'UTF-8')})
                etotp = datadict['TOTP']
                if etotp == "":
                    totpcalc = "N/A"
                else:
                    totpbytes = eval(bytes(etotp, 'UTF-8'))
                    decrytpedtotp = keys.decrypt(totpbytes)
                    padding_length2 = decrytpedtotp[-1]
                    plaintext_bytes2 = decrytpedtotp[:-padding_length2]
                    totpstr = str(plaintext_bytes2, 'UTF-8')
                    try:
                        totp = pyotp.TOTP(totpstr)
                        totpcalc = totp.now()
                    except Exception as e:
                        totpcalc = "improper TOTP secret please edit your TOTP"
                pk = datadict['pk']
                pwpk = PW.objects.get(pk=pk)
                pw_url= pwpk.get_absolute_url()
                notes1 = datadict['Notes']
                url1 = datadict['URL']
                data_dict = {
                "Username": username,
                "Password": password,
                "TOTP": totpcalc,
                "URL" : url1,
                "notes" : notes1,
                "EditURL": pw_url
            }
                mainlist.append(data_dict)
        return render (request, 'pw_homepage.html', {'pwlist': mainlist})
    else:
         return render(request, 'pin.html')

@login_required
def Edit(request, pk):
    pw = get_object_or_404(PW, pk=pk)
    ekey = Encryption.objects.get(Owner=request.user)
    salt = bytes(ekey.Salt,'UTF-8')
    if request.method == 'POST':
       pin = bytes(request.POST.get('pin'), 'UTF-8')
       key = bcrypt.kdf(pin, salt, rounds=500, desired_key_bytes=32)
       form = PwEdit(request.POST, request.FILES, instance=pw)
       if form.is_valid():
            pw.Password = crypto.encrypt(form.cleaned_data.get('Password'), key, request.user, )
            pw.TOTP = crypto.encrypt(form.cleaned_data.get('TOTP'), key, request.user)
            pw.save()
            form.save()
            return redirect('/')
    else:
        if request.method =='GET':
            try:
                if pw.Owner != request.user:
                    return JsonResponse({'msg': "ACCESS DENIED"}, status=403)
                data = request.GET.get("pin")
                pin = bytes(data, 'UTF-8')
                key = bcrypt.kdf(pin, salt,rounds=500,  desired_key_bytes=32)
                form_initial = crypto.decryptform( pw, key, request.user)
                form = PwEdit(instance=pw, initial=form_initial)
                return render(request, 'form.html', {'form': form})
            except Exception as e:
                return render(request, 'pinget.html')

@login_required
def Destory(request, pk):
    pw = get_object_or_404(PW, pk=pk)
    if request.method == 'POST':
        if pw.Owner == request.user:
            pw.delete()
            return redirect('/')
        else:
             return JsonResponse({'msg': "ACCESS DENIED"})
    else:
        return render(request, "delete.html")