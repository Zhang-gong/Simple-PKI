import hashlib
import uuid
import time
import calendar;
import os
import csv
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key,load_pem_public_key

key_storage=[]
key = {'keygen':'','time':'','timestamp':0}
KEY_FILE_PATH = "key.csv"
HEADER = ['user_subject_name', 'public_key', 'private_key', 'created_time']


banner ='''
please input your choice of functions:
1 - create key
2 - show keys
3 - delete key
'''

def get_private_pem(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem
def get_public_pem(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem
def load_private_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()

    private_key = load_pem_private_key(pemlines, None, default_backend())
    # print("load key successful")
    return private_key

def load_public_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()

    public_key = load_pem_public_key(pemlines, default_backend())
    print("load key successful")
    return public_key
def save_key(private_key, public_key,user_subject_name):
    created_time = calendar.timegm(time.gmtime())
    private_key_bytes=get_private_pem(private_key)
    public_key_bytes=get_public_pem(public_key)
    #data = [user_subject_name.encode('utf-8'),public_key_bytes,private_key_bytes,str(created_time).encode('utf-8')]

    public_key_file_name='ca_key\\'+user_subject_name+'.public'
    private_key_file_name='ca_key\\'+user_subject_name+'.private'

    with open(private_key_file_name, 'wb') as file:
        file.write(private_key_bytes)
        print('private key of '+user_subject_name+' has saved')
    with open(public_key_file_name, 'wb') as file:
        file.write(public_key_bytes)
        print('public key of'+user_subject_name+' has saved')


def key_construct():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_numeric = int.from_bytes(public_key_bytes, byteorder='big')
    print("Public Key (Numeric):", public_key_numeric)

    private_key_numeric = int.from_bytes(private_key_bytes, byteorder='big')
    print("Private Key (Numeric):", private_key_numeric)

    return private_key, public_key



