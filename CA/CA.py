from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.serialization import load_pem_private_key,load_pem_public_key
import kms
import pickle
# 1. 生成CA密钥对
def generate_ca_key_pair(user_name):
    private_key, public_key=kms.key_construct()
    kms.save_key(private_key, public_key,user_name)
    print("generate key of "+user_name+"Successfully")
# 2. 证书签发
def issue_certificate(ca_private_key, user_public_key, subject_name):
    #这里的user是相对于CA的user,包括ssh服务器和ssh用户
    # 构建证书主题
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])

    # 构建证书的有效期
    valid_from = datetime.utcnow()
    valid_to = valid_from + timedelta(days=365)

    # 创建一个证书签发请求
    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject  # 使用CA的主题作为颁发者名称
    ).public_key(
        user_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        valid_from
    ).not_valid_after(
        valid_to
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )

    # 使用CA私钥签发证书
    certificate = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    # 保存证书到文件
    with open("cert\\"+subject_name+"_cert.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    # 保存CA私钥到文件（这里仅供演示，实际应用中应更加安全地保存）
    # with open("ca_key.pem", "wb") as f:
    #     f.write(ca_private_key.private_bytes(
    #         encoding=serialization.Encoding.PEM,
    #         format=serialization.PrivateFormat.PKCS8,
    #         encryption_algorithm=serialization.NoEncryption()
    #     ))

    return certificate

# 3. 证书验证
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
        print("VERIFY FAILED:", e)
        return False

# 4. 证书撤销（这里仅演示，实际应用中需要更复杂的实现）
revoked_certificates = set()

def revoke_certificate(certificate_serial_number):
    revoked_certificates.add(certificate_serial_number)


# 示例
if __name__ == "__main__":
    banner = '''
    please input your choice of functions:
    1 - generate CA host/user's key
    2 - CA issues host certificates
    3 - CA issues user certificates
    '''
    print('Welcome to CA')
    choice = int(input(banner))
    while (choice != 0):
        match choice:
            case 1:
                # 生成密钥
                generate_ca_key_pair( "user_ca")
                generate_ca_key_pair("host_ca")
            case 2:
                host_ca_private_key_file_path = 'ca_key\\host_ca.private'  # ca的密钥
                ssh_host_public_key_file_path = 'user_host_key\\ssh_host_rsa_key.public'  # host的公钥

                host_ca_private_key = kms.load_private_key(host_ca_private_key_file_path)
                ssh_host_public_key = kms.load_public_key(ssh_host_public_key_file_path)


                certificate = issue_certificate(host_ca_private_key, ssh_host_public_key, "host")
                print("CA issues host certificates successfully")
            case 3:
                user_ca_private_key_file_path = 'ca_key\\user_ca.private'  # ca的密钥
                ssh_user_public_key_file_path = 'user_host_key\\ssh_user_rsa_key.public'  # user的公钥

                user_ca_private_key = kms.load_private_key(user_ca_private_key_file_path)
                ssh_user_public_key = kms.load_public_key(ssh_user_public_key_file_path)


                certificate = issue_certificate(user_ca_private_key, ssh_user_public_key, "user")
                print("CA issues user certificates successfully")

            case _:
                print('Error')

        choice = int(input(banner))
    print('CA Shutdown!')

