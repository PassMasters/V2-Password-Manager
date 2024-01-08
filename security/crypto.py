import base64
import os
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pwmanager.models import PW, Encryption, Data_ID, PWcheck
import cryptography
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
def decryptform( obj, key, user):
        dID = Data_ID.objects.get(User=user)
        ekey = Encryption.objects.get(Owner_ID=dID.Key_lookup)
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
             from_initial = {
                  'Password': v2,
                  'TOTP': "N/A"
             }
             return from_initial
        form_initial = {
            'Password': v2,
            'TOTP': x3
            }
        return form_initial
def encrypt(obj, key, user, iv):
    ekey = Encryption.objects.get(Owner=user)
    keys = AES.new(key, AES.MODE_CBC, iv)
    v1 = bytes(obj, 'UTF-8')
    padding_length = 16 - (len(v1) % 16)
    plaintext_bytes = v1 + bytes([padding_length]) * padding_length
    v2 = keys.encrypt(plaintext_bytes)
    return v2
