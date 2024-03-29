import os
from pwmanager.models import Encryption
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from django.conf import settings
BASE_DIR = settings.BASE_DIR
def RSAdecryptmessage(message):
     server_private = RSA.import_key(open(os.path.join(BASE_DIR, 'private.pem')).read())
     cipher_server = PKCS1_OAEP.new(server_private)
     val = cipher_server.decrypt(message)
     s1 = str(val, 'UTF-8')
     return s1
def RSAencryptmessage(msg, pubkey):
     key = RSA.import_key(pubkey)
     cipher = PKCS1_OAEP.new(key)
     ciphertext = cipher.encrypt(msg)
     return ciphertext
def decrypt(item, key):
    keys = key
    d7 = keys.decrypt(item)
    padding_length = d7[-1]
    plaintext_bytes = d7[:-padding_length]
    v2 = str(plaintext_bytes,'UTF-8')
    return v2
def encrypt2(item, key):
    
    v1 = item
    padding_length = 16 - (len(v1) % 16)
    padded_bytes = v1 + bytes([padding_length]) * padding_length
    
    d7 = key.encrypt(padded_bytes)
    return d7

def decryptform( obj, key, user):
        ekey = Encryption.objects.get(Owner=user)
        v7 = eval(bytes(obj.Password, 'UTF-8'))
        iv = eval(bytes(ekey.IV, 'UTF-8'))
        keys = AES.new(key, AES.MODE_CBC, iv)
        x0 = keys.decrypt(v7)
        padding_length = x0[-1]
        plaintext_bytes = x0[:-padding_length]
        v2 = str(plaintext_bytes,'UTF-8')
        try:
              
            x1 = eval(bytes(obj.TOTP, 'utf-8'))
            x2 = keys.decrypt(x1)
            padding_length = x2[-1]
            plaintext_bytes = x2[:-padding_length]
            x3 = str(plaintext_bytes,'UTF-8')
        except Exception as e:
             form_initial = {
                  'Password': v2,
                  'TOTP': "N/A"
             }
             return form_initial
        form_initial = {
            'Password': v2,
            'TOTP': x3
            }
        return form_initial
def encrypt(obj, key, user):
    ekey = Encryption.objects.get(Owner=user)
    iv = eval(bytes(ekey.IV, 'UTF-8'))
    keys = AES.new(key, AES.MODE_CBC, iv)
    v1 = obj
    padding_length = 16 - (len(v1) % 16)
    try:
        plaintext_bytes = v1 + bytes([padding_length]) * padding_length
    except Exception:
         v1 = bytes(obj, 'UTF-8')
         padding_length = 16 - (len(v1) % 16)
         plaintext_bytes = v1 + bytes([padding_length]) * padding_length
    v2 = keys.encrypt(plaintext_bytes)
    return v2
