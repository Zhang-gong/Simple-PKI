Environment:

python==3.9.13
```
pip3 install -r requirements.txt
```
start three terminals:
```
python CA.py
python client.py
python server.py
```

The simulation is performed in the following order

CA:input 1 - generate CA host/user's key

SERVER：input 1 - generate local server private/public key and give public key to CA 

CLIENT:input 1 - generate local client private/public key and give public key to CA

CA:input 2 - CA issues host certificates

CA:input 3 - CA issues user certificates

SERVER:input 2 - get host certificate and user_ca.public key

CLIENT:input 2 - get user certificate and host_ca.public key

-----ssh start-----

CLIENT:input 3 - ssh log in the server(host), automatically sends the client(user) certificate to the server(host)

SERVER:input 3 - verify the certificate from client(user) and send the server(host) certificate to client(user)

CLIENT:input 4 - verify the certificate from server(host)


clean.py can clean all generated certificates and public and private keys.

```
python clean.py
```
