import socket
import ssl
import hashlib

# 导入KMS模块中的相关函数和变量
from kms import key_storage, key_construct, load_key, save_key
from CA import generate_ca_key_pair, issue_certificate,verify_certificate,revoke_certificate

def handle_client(client_socket):
    client_cert = client_socket.getpeercert(binary_form=True)
    if verify_certificate(client_cert, ca_public_key):
        print("Client certificate verified and trusted.")
    else:
        print("Client certificate verification failed. Closing connection.")
        client_socket.close()
        return

    load_key()

    # 在这里实现SSH协议的具体逻辑，使用KMS模块来生成和管理密钥

    # 假设接收到客户端请求，需要生成新的密钥
    key_construct()  # 这里可以根据具体的SSH协议实现来生成密钥

    # 假设服务器需要发送一个包含密钥信息的消息给客户端
    # 这里简单地使用字符串作为消息，实际中应该根据协议来封装消息
    message = "New key generated: {}".format(key_storage[-1]['keygen'])
    client_socket.send(message.encode())

    client_socket.close()
    save_key()  # 保存密钥

# 创建CA实例
ca_private_key, ca_public_key = generate_ca_key_pair()

# 签发服务器证书
server_cert = issue_certificate(ca_private_key, ca_public_key, "Server")

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")
context.load_verify_locations(cafile="ca_cert.pem")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 22))  # 使用SSH默认端口号22
server_socket.listen(1)

print("Waiting for client connections...")

while True:
    client_socket, client_address = server_socket.accept()
    secure_client_socket = context.wrap_socket(client_socket, server_side=True)
    print(f"Accepted connection from {client_address}")

    # 处理客户端请求
    handle_client(secure_client_socket)
