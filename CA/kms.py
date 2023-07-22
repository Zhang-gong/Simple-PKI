import hashlib
import uuid
import time
import calendar;
import os

key_storage=[]
key = {'keygen':'','time':'','timestamp':0}

secret = str(uuid.uuid1())[-12:] + '.key' #server mac address

banner ='''
please input your choice of functions:
1 - create key
2 - show keys
3 - delete key
'''

def load_key():
    if os.path.exists(secret) !=True:
        print('No local key')
        return
    t = calendar.timegm(time.gmtime())
    f = open(secret, 'r')
    for line in f.readlines():
        print(line)
        line = line.strip()
        line = line.split(':')
        key['keygen'] = line[0]
        key['time'] = int(line[1])
        key['timestamp'] = int(line[2])
        if key['timestamp'] + key['time'] > t :
            print('Key:%s live' % key['keygen'])
            key_storage.append(key)
    f.close()
    print('living key has loaded')
    file = open(secret, 'w').close()
    
def save_key():
    t = calendar.timegm(time.gmtime())
    with open("server_key.pem", 'a') as f:
        for item in key_storage:
            if item['time'] + item['timestamp'] > t:
                output = item['keygen'] +':'+ str(item['time']) +':'+ str(item['timestamp']) +':'+ item['keygen'][-12:]+'\n'
                print(output)
                print(f)
                f.write(output)
                print(output)
    print('living key has saved')

def key_construct():
    keygen = ''.join(str(uuid.uuid4()).split('-'))[:20]+str(uuid.uuid1())[-12:] #应用于协议后此处应修改，修改为uuid4+客户端mac地址
    t = calendar.timegm(time.gmtime())
    key = {'keygen':keygen, 'time':t, 'timestamp':3600}
    key_storage.append(key)
    print('New keygen: %s is constructed for 3600s' % keygen)
      

if __name__ == '__main__':
    load_key()
    print('Welcome to KMS')
    choice = int(input(banner))
    while(choice != 0):
        match choice:
            case 1:
                key_construct() #协议：输入参数为客户端mac地址
               
            case 2:
                if len(key_storage) > 0 :
                    for item in key_storage:
                        print('Keygen: %s ,startime: %s, from user:%s' % (item['keygen'],str(item['time']),item['keygen'][-12:]))
                else:
                    print('暂无密钥')
            case 3:
                keygen = input('please input a keygen:')
                key_storage = key_storage.sort(key = lambda x:x[0]!=keygen)
                if key_storage[0]['keygen'] == keygen:
                    key_storage.pop(0)
                    print('Delete !')
                else:
                    print('Not Found')
            case _:
                print('Error')
        
        choice = int(input(banner))
    save_key()
    print('Service dowm!')
