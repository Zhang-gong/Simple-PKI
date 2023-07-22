import socket
import ssl

# 创建CA实例
ca_private_key, ca_public_key = generate_ca_key_pair()

# 签发客户端证书
client_cert = issue_certificate(ca_private_key, ca_public_key, "Client")

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_cert_chain(certfile="path/to/client_cert.pem", keyfile="path/to/client_key.pem")
context.load_verify_locations(cafile="path/to/ca_cert.pem")

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
secure_client_socket = context.wrap_socket(client_socket, server_hostname="Server")

secure_client_socket.connect(('127.0.0.1', 22))  # 使用SSH默认端口号22

# 假设客户端需要发送一个请求给服务器
# 这里简单地使用字符串作为请求，实际中应该根据协议来封装请求
request = "Generate new key"
secure_client_socket.send(request.encode())

response = secure_client_socket.recv(1024)
print(response.decode())

secure_client_socket.close()
