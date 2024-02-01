import json
from django.shortcuts import render
from . import models
from django.shortcuts import render, get_object_or_404
import uuid
from django.http import JsonResponse
from django.shortcuts import redirect
from .models import RegDevice, LinkedUser, AcessRequest, ConfCode
import jwt
import os
from Crypto.PublicKey import RSA
import secrets
import bcrypt
from Crypto.Cipher import AES
from django.contrib.auth.decorators import login_required
import hashlib
from pwmanager.models import PW, Encryption
from datetime import datetime, timedelta
from django.contrib.auth.models import User
from security import crypto as crypt
from security.models import UserServerKeys as userkeys
from security.models import PWcheck

# Create your views here.

def obtain(request):
    if request.method != 'POST':
        return render(request, 'lisence/index.html')
    else:
        #gen uuid
        model = models.apikey()

        model.name = request.POST.get('name')
        model.key = uuid.uuid4()
        model.Type = "Normal"
        model.Activations = 0
        model.Limit = 5
        model.save()
        context = {'generated_uuid': str(model.key)}
        return render(request, 'lisence/key.html', context)
    
@login_required
def Aprove(request, pk):
    model = get_object_or_404(AcessRequest, pk=pk)
    if request.method == "GET":
        context = {
            'perm1': model.perm1, 
            'perm2': model.perm2
        }
        return render(request, "acessdetails.html", context)
    else:
        pwcheck = PWcheck.objects.get(Owner=request.user)
        ekey = Encryption.objects.get(Owner=request.user)
        salt = eval(bytes(ekey.Salt,'UTF-8'))
        iv = eval(bytes(ekey.IV, 'UTF-8'))

        pin = bytes(request.POST.get('pin'), 'UTF-8')
        encryption_key = bcrypt.kdf(pin, salt,rounds=500,  desired_key_bytes=32)
        keys = AES.new(encryption_key, AES.MODE_CBC, iv)
        answer = pwcheck.Answer
        data = eval(bytes(pwcheck.Data, 'UTF-8'))
        datade = keys.decrypt(data)
        padding_length = datade[-1]
        plaintext_bytes = datade[:-padding_length]
        datade = str(plaintext_bytes, 'UTF-8')
        if datade != answer:
            context = {
                'error': "wrong pin"}
            return render(request, "acessdetails.html", context)
        conf = ConfCode()
        model.aproval = True
        model.save()
        userkey = userkeys()
        linkeduser = LinkedUser()
        linkeduser.User = request.user
        linkeduser.Device = RegDevice.objects.get(Serial=model.Serial)
        linkeduser.key = model.key
        linkeduser.premisions = model
        linkeduser.save()
        userkey.Owner = request.user
        key = os.urandom(32)
        iv = os.urandom(16)
        keys2 = AES.new(key, AES.MODE_CBC, iv)
        userkey.IV = iv
        result = keys2.encrypt(encryption_key)
        print(result)
        userkey.key = result
        userkey.save()
        conf.req = model
        conf.key = key
        resultcode = secrets.randbelow(9000000000)
        conf.code = resultcode
        conf.save()
        return render(request, "sucess.html", {'code': resultcode})

def TOTP(request):
    if request.method != 'POST':
        return JsonResponse({'status':"POST request Required"})
    else:
        key = bytes(request.POST.get('ekey'), 'UTF-8')
        serial = request.POST.get('serial')
        lisence = request.POST.get('token')
        model = models.RegDevice.objects.get(Serial=serial)
        if lisence != model.key:
            return JsonResponse({'status':"Lisence does not match and go die!"})
        perms = models.LinkedUser.objects.get(Device=model)
        user = request.POST.get('user')
        userobj = User.objects.get(username=user)
        if perms.User != userobj:
            return JsonResponse({'status':"User does not match and go die!"})
        perms2 = models.AcessRequest.objects.get(pk=perms.premisions.pk)
        if perms2.aproval == False:
            return JsonResponse({'status':"NOT ALLOWED GO DIE!"})
        perm1 = perms2.perm1
        if perm1 == 'NONE':
            return JsonResponse({'status':"NOT ALLOWED GO DIE!"})
        else:
            if perm1 != "Read All TOTP Secrets":
                return JsonResponse({'status':"NOT ALLOWED GO DIE!"})
        pw = PW.objects.filter(Owner=userobj).values('TOTP', 'URL', 'Username')
        ekey =  Encryption.objects.get(Owner=userobj)
        iv = eval(bytes(ekey.IV,'UTF-8'))
        keys = AES.new(key, AES.MODE_CBC, iv)
        totplist = list(pw)
        mainlist = []
        for i in range(len(totplist)):
            datadict = dict(totplist[i])
            TOTPbytes = eval(bytes(datadict['TOTP'], 'UTF-8'))
            username = datadict['Username']
            url1 = datadict['URL']
            dtotp  = crypt.decrypt(TOTPbytes, keys)
            data_dict = {
                "Username": username,
                "TOTP": dtotp,
                "URL" : url1,
            }
            mainlist.append(data_dict)
        context = {'data': mainlist}
        return JsonResponse(context)
def ConfVerify(request, pk):
    model = get_object_or_404(ConfCode, pk=pk)
    if request.method != 'POST':
        return JsonResponse({'status': "wrong request method"}, status=500)
    else:
        req = AcessRequest.objects.get(pk=model.req.pk)
        userobj = User.objects.get(pk=req.user.pk)
        if req.aproval==True:
            serverkey = userkeys.objects.get(Owner=userobj)
            iv = eval(bytes(serverkey.IV, 'UTF-8'))
            key = model.key
            keys = AES.new(key, AES.MODE_CBC, iv)
            result = keys.decrypt(eval(bytes(userkeys.key, 'UTF-8')))
            context = {'data': result}
            serverkey.delete()
            model.key = os.urandom(32)
            model.save()
            return JsonResponse(context, status=200)
        else:
            context = {'status': 'DENIED'}
            return JsonResponse(context, status=401)

def acessrequestcode(request):
    if request.method != 'POST':
        return  JsonResponse({'error':'Improper request'}, status=403)
    else:
        perm1 = request.POST.get('Perm1')
        perm2 = request.POST.get('Perm2')
        token = request.POST.get('key')
        serail = request.POST.get('Serial')
        try:
            model = models.apikey.objects.get(key=token)
        except Exception:
            return JsonResponse({'status':"key does not exsit"}, status=401)
        user = request.POST.get('username')
        userobj = User.objects.get(username=user)
        code = secrets.randbelow(9000000000)
        model = AcessRequest()
        model.key = token
        model.perm1= perm1
        model.perm2 = perm2
        model.code = code
        model.user = userobj
        model.Serial = serail
        model.save()
        return JsonResponse({'code': code,'status':"sucess"}, status=200)
def Deactveate(request):
    if request.method != 'POST':
        return render(request, 'lisence/index.html')
    else:
        token = request.POST.get('key')
        model = models.apikey()
        try:
            model = models.apikey.objects.get(key=token)
        except models.apikey.DoesNotExist:
            return JsonResponse({'error': 'Invalid token'}, status=403)
        model.Activations = model.Activations - 1
        model.save()
        return JsonResponse({'result': 'Deactivated'}, status=200)


def TokenRequest(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'})
    else: 
        token = request.POST.get('key')
        model = models.apikey()
        try:
            model = models.apikey.objects.get(key=token)
        except models.apikey.DoesNotExist:
            return JsonResponse({'error': 'Invalid token'}, status=403)
        model.Activations = model.Activations + 1
        if model.Activations > model.Limit:
            return JsonResponse({'error': 'limit reached'}, status=403)
        model.save()
        my_uuid = token
        expiration_time = datetime.utcnow() + timedelta(days=30)
        reg = RegDevice()
        serial = secrets.randbelow(92384923742349)
        siginkey = str(uuid.uuid4())
        reg.Serial = serial
        reg.key =  siginkey
        reg.save()
        secret = b'OIDFJIODSFJIODSFJIU(WFHOISDF903248uweriy87345ureiyrtb965258752475201258525475sduri6838ejmfiuvmknmeujdjedjdjjdjdjdjd)'
        payload = {
        'uuid': my_uuid,
        'Serial ':  serial,
        'signingkey': siginkey,
        'Server Key': 'OIDFJIODSFJIODSFJIU(WFHOISDF903248uweriy87345ureiyrtb965258752475201258525475sduri6838ejmfiuvmknmeujdjedjdjjdjdjdjd)',
        'exp': expiration_time,
    }
        token = jwt.encode(payload, secret, algorithm='HS256')
        context = {'token': token}
        return JsonResponse(context, status=200, safe=False)
