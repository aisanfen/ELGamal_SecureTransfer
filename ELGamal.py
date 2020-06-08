# ElGamal encryC1tion
import random
import os
import numpy as np
from PIL import Image

from tkinter import _flatten

from math import pow
a = random.randint(2, 10)

def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)



#产生大随机数
def gen_key(p):
    key = random.randint(pow(10, 20), p)
    while gcd(p, key) != 1: #(互素)
        key = random.randint(pow(10, 20), p)

    return key



# 模重复平方算法
def ModSqu(b,m,n):  # b^m mod n
    box = str(bin(m)).replace("0b", "")
    s = 1
    length = len(box)
    for index, value in enumerate(box):
        if int(box[length - index - 1]) == 1:
            s = (s * b) % n
        b = (b * b) % n
    return s

# 非对称加密运算
def encrypt(msg, p, y, g,C1,C2):
    en_msg = []
    for i in range(0, len(msg)):
        en_msg.append(msg[i])

    for i in range(0, len(en_msg)):
        en_msg[i] = C2 * ord(en_msg[i])

    return en_msg


# 解密
def decrypt(en_msg, C1, key, p):
    dr_msg =[]
    y = ModSqu(C1, key, p)
    print("y = ",y)
    for i in range(0, len(en_msg)):    #c1^-x*c2modp   也就是demsg = enmesg /(c1^kmod p)
        # print('进行解密',en_msg[i])
        txt=int(en_msg[i] / y)
        dr_msg.append(chr(txt))
    return dr_msg




# 加密文件
def encode_file(filepath):
    f_name = os.path.basename(filepath)
    # print(f_name)
    f_type = os.path.splitext(f_name)
    # print(f_type)
    filename, type = f_type
    # print(filename,type)

    p = random.randint(pow(10, 30), pow(10, 50))
    g = random.randint(2, p)
    key = gen_key(p)  # 产生接收者私钥
    y = ModSqu(g, key, p)
    print("g used : ", g)
    print("y used : ", y)
    k = gen_key(p)  # 发送者密钥
    C1 = ModSqu(g, k, p)
    C2 = ModSqu(y, k, p)
    print("C1 used : ", C1)
    print("C2 used : ", C2)
    private_path='ELGamal/private/'+str(f_name)
    with open(private_path, 'w') as enfile:
        enfile.write(''.join(str(C1)) + "\n")
        enfile.write(''.join(str(key)) + '\n')
        enfile.write(''.join(str(p)) + '\n')



    if type == '.txt':
        with open(filepath, 'r',encoding='UTF-8') as f:
            msg = f.read()
        print("Original Message :\n", msg)
        en_msg = encrypt(msg, p, y, g, C1, C2)
        # print(en_msg)
        savepath = 'ELGamal/client/' + str(f_name)
        with open(savepath, 'w') as f:
            f.write(str(en_msg))
    else:
        savepath=filepath
    return savepath

def uncode_file(filename):
    # print("Attain the private key")
    # 读取密钥
    private_path = 'ELGamal/private/' + str(filename)
    with open(private_path, 'r') as defile:
        delist = defile.read().split()
        # print(delist)
    C1 = int(delist[0])
    key = int(delist[1])
    p = int(delist[2])
    # print('C1=', str(C1))
    # print('key=', str(key))
    # print('p=', str(p))

    dmsg = []
    filepath='ServerRec/'+str(filename)
    with open(filepath, 'r',encoding='UTF-8') as defile:
        for line in defile.readlines():
            line = line.strip('[')  # 去首尾字符 []1
            line = line.strip(']')
            if line:
                ls = line.split(',')
        linestrlist = [int(i) for i in ls]
    dr_msg = decrypt(linestrlist, C1, key, p)
    dmsg = ''.join(dr_msg)  # 字符拼接
    # print("Decrypted Message :\n", dmsg)
    serverpath = 'ELGamal/serverfile/' + str(filename)
    with open(serverpath, 'w') as f:
        f.write(str(dmsg))
    return serverpath

if __name__=="__main__":
    filepath='1.txt'
    encode_file(filepath)
    print(encode_file(filepath))
    print(uncode_file('ELGamal/client/1.txt'))






