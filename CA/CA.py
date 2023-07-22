from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

# 1. 生成CA密钥对
def generate_ca_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# 2. 证书签发
def issue_certificate(ca_private_key, ca_public_key, subject_name):
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
        ca_public_key
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
    with open("server_cert.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    # 保存CA私钥到文件（这里仅供演示，实际应用中应更加安全地保存）
    with open("ca_key.pem", "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))  

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
        print("证书验证失败:", e)
        return False

# 4. 证书撤销（这里仅演示，实际应用中需要更复杂的实现）
revoked_certificates = set()

def revoke_certificate(certificate_serial_number):
    revoked_certificates.add(certificate_serial_number)

# 示例
if __name__ == "__main__":
    # 生成CA密钥对
    ca_private_key, ca_public_key = generate_ca_key_pair()

    # 签发证书
    user_subject_name = "User A"
    certificate = issue_certificate(ca_private_key, ca_public_key, user_subject_name)
    
    # 验证证书
    is_valid = verify_certificate(certificate, ca_public_key)
    print("证书有效性:", is_valid)

    # 撤销证书（示例中没有涉及证书序列号的提取，实际应用中需要提取证书序列号来进行撤销）
    certificate_serial_number = certificate.serial_number
    revoke_certificate(certificate_serial_number)

    # 再次验证证书（现在应该验证失败）
    is_valid_after_revocation = verify_certificate(certificate, ca_public_key)
    print("证书在撤销后的有效性:", is_valid_after_revocation)
