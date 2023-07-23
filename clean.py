# -*- coding:utf-8 -*-
"""
Created on  # 17:25  17:25
@author: Gong Zhang
"""

#delete private key or public key or certificate
import os
path = "."
for root, dirs, files in os.walk(path, topdown=False):
    for name in files:
        if name.endswith('.public',) or name.endswith('.pem',) or name.endswith('.private',):
            print("delete:"+name)
            os.remove(os.path.join(root, name))