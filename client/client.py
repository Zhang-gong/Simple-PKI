import socket
import hashlib
import socket
import hashlib
import calendar
import os
import csv
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import shutil
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key,load_pem_public_key

HEADER = ['user_subject_name', 'public_key', 'private_key', 'created_time']


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
def save_key(private_key, public_key,user_subject_name):
    created_time = calendar.timegm(time.gmtime())
    private_key_bytes=get_private_pem(private_key)
    public_key_bytes=get_public_pem(public_key)

    public_key_file_name='client_key\\'+user_subject_name+'.public'
    private_key_file_name='client_key\\'+user_subject_name+'.private'

    with open(private_key_file_name, 'wb') as file:
        file.write(private_key_bytes)
        print('private key of'+user_subject_name+' has saved')
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

def copy_file(source_file_path, target_file_path):
    try:
        shutil.copyfile(source_file_path, target_file_path)
        print(f"File copied from '{source_file_path}' to '{target_file_path}' successfully.")
    except FileNotFoundError:
        print("Source file not found.")
    except PermissionError:
        print("Permission denied. Unable to copy the file.")

def verify_certificate(certificate, ca_public_key):
    try:
        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
        return True
    except Exception as e:
        print("verify failed:", e)
        return False

def load_certificate(file_path):
    with open(file_path, "rb") as f:
        certificate_data = f.read()
        certificate = x509.load_pem_x509_certificate(certificate_data, default_backend())
        return certificate

def load_public_key(filename):
    with open(filename, 'rb') as pem_in:
        pemlines = pem_in.read()

    public_key = load_pem_public_key(pemlines, default_backend())
    # print("load key successful")
    return public_key
def generate_ca_key_pair(server_name):
    private_key, public_key=key_construct()
    save_key(private_key, public_key,server_name)
    return private_key, public_key
if __name__ == "__main__":
    banner = '''
    please input your choice of functions:
    1 - generate local client private/public key and give public key to CA 
    2 - get user certificate and host_ca.public key
    ----------------------------------------------
    3 - ssh log in the server(host), automatically sends the client(user) certificate to the server(host)
    4 - verify the certificate from server(host)
    '''
    print('Welcome to user')
    choice = int(input(banner))
    while (choice != 0):
        match choice:
            case 1:
                # 生成密钥
                server_name = "ssh_user_rsa_key"
                ca_private_key, ca_public_key = generate_ca_key_pair(server_name)
                source_file_path = 'client_key\\ssh_user_rsa_key.public'
                target_file_path = '..\\CA\\user_host_key\\ssh_user_rsa_key.public'
                copy_file(source_file_path, target_file_path)
            case 2:
                source_file_path = '..\\CA\\cert\\user_cert.pem'
                target_file_path = 'client_cert\\user_cert.pem'
                copy_file(source_file_path, target_file_path)
                print("I have certificate now!")
                source_file_path = '..\\CA\\ca_key\\host_ca.public'
                target_file_path = 'verify\\host_ca.public'
                copy_file(source_file_path, target_file_path)
                print("I have host_ca.public now!")
            case 3:
                print("Initiate an ssh connection and send client(user) certificate")
                source_file_path = 'client_cert\\user_cert.pem'
                target_file_path = '..\\server\\verify\\user_cert.pem'
                copy_file(source_file_path, target_file_path)
                print("certificate sent!")
            case 4:
                print("Start to verify the certificate from server(host)")
                host_certificate_path = "verify\\host_cert.pem"
                host_public_key_path = "verify\\host_ca.public"
                host_certificate = load_certificate(host_certificate_path)
                host_ca_public_key = load_public_key(host_public_key_path)
                is_valid = verify_certificate(host_certificate, host_ca_public_key)
                print("Certificate validity:", is_valid)
                if is_valid:
                    print("--------ssh connection established!--------")
            case _:
                print('Error')

        choice = int(input(banner))
    print('user shutdown!')

