---
title: How Does the CBC-MAC Algorithm Work?
published: true
---

<p align="center">
  <img width="460" height="300" src="/assets/CBC-MAC-2.png">
</p>

In this article, you will understand how the cbc-mac algorithm works and you will be tested with a challenge.

### [](#header-3)How does the CBC-MAC algorithm work?
The basic structure of Cipher Block Chaining is given by the diagram above. The message is chopped up into blocks of equal size (with necessary padding). The first block is XORed with an initialization vector and the resulting block is encrypted using a secret key. The encrypted output becomes the initialization vector for the next block, and so on.

With Message Authentication Code, the idea is that an entire message is treated with CBC and only the cipher output of the last block is provided as a proof of authenticity. The principle is that if the message is tampered in any way, the intermediate ciphers will change, creating a cascading effect and invalidate the final cipher.

### [](#header-3)Challenge!
Create a flag.txt file in the same directory as the script below and run the script. This will be our fault.

```
# This script belongs to the question CBC-MAC-1 on UMD-CTF.
import socket
import threading
from _thread import *
from Crypto import Random
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify

HOST = '0.0.0.0'  # Standard loopback interface address (localhost)
PORT = 60001        # Port to listen on (non-privileged ports are > 1023)
FLAG = open('flag.txt', 'r').read().strip()
MENU = "\nWhat would you like to do?\n\t(1) MAC Query\n\t(2) Forgery\n\t(3) Exit\n\nChoice: "
INITIAL = "Team Rocket told me CBC-MAC with arbitrary-length messages is safe from forgery. If you manage to forge a message you haven't queried using my oracle, I'll give you something in return.\n"

BS = 16 # Block Size
MAX_QUERIES = 10
   
def cbc_mac(msg, key):
    iv = b'\x00'*BS
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    t = cipher.encrypt(msg)[-16:]
    return hexlify(t)

def threading(conn):
    conn.sendall(INITIAL.encode())

    key = Random.get_random_bytes(16)
    queries = []
    while len(queries) < MAX_QUERIES:
        conn.sendall(MENU.encode())
        try:
            choice = conn.recv(1024).decode().strip()
        except ConnectionResetError as cre:
            return

        # MAC QUERY
        if choice == '1':
            conn.sendall(b'msg (hex): ')
            msg = conn.recv(1024).strip()

            try:
                msg = unhexlify(msg)
                if (len(msg) + BS) % BS != 0:
                    conn.sendall(f'Invalid msg length. Must be a multiple of BS={BS}\n'.encode())
                else:
                    queries.append(msg)
                    t = cbc_mac(msg, key)
                    conn.sendall(f'CBC-MAC(msg): {t.decode()}\n'.encode())
            except Exception as e:
                conn.sendall(b'Invalid msg format. Must be in hexadecimal\n')

        # FORGERY (impossible as I'm told)
        elif choice == '2':
            conn.sendall(b'msg (hex): ')
            msg = conn.recv(1024).strip()
            conn.sendall(b'tag (hex): ')
            tag = conn.recv(1024).strip()

            try:
                msg = unhexlify(msg)
                if (len(msg) + BS) % BS != 0:
                    conn.sendall(f'Invalid msg length. Must be a multiple of BS={BS} bytes\n'.encode())
                elif len(tag) != BS*2:
                    conn.sendall(f'Invalid tag length. Must be {BS} bytes\n'.encode())
                elif msg in queries:
                    conn.sendall(f'cheater\n'.encode())
                else:
                    t_ret = cbc_mac(msg, key)
                    if t_ret == tag:
                        conn.sendall(f'If you reach this point, I guess we need to find a better MAC (and not trust TR). {FLAG}\n'.encode())
                    else:
                        conn.sendall(str(t_ret == tag).encode() + b'\n')
            except Exception as e:
                conn.sendall(b'Invalid msg format. Must be in hexadecimal\n')

        else:
            if choice == '3': # EXIT
                conn.sendall(b'bye\n')
            else: # INVALID CHOICE
                conn.sendall(b'invalid menu choice\n')
            break


    if len(queries) > MAX_QUERIES:
        conn.sendall(f'too many queries: {len(queries)}\n'.encode())
    conn.close()


if __name__ == "__main__":
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            print(f'new connection: {addr}')
            start_new_thread(threading, (conn, ))
        s.close()


```

You can try to solve it first. The solution is as follows:

We will send one block of known plain text A (b’aaaaaaaaaaaaaaaa’) and recieve a tag (T1)
We will calculate the XOR value of the plain text and the tag (E = A xor T1)
We will append this calculated value to the original plain text and send it for the forgery option, with the expected tag of T1

### [](#header-3)Why does this work ?

```
T1 = Encryption(A , key)
E = A xor T1

When we send a message A||E,
A being the first block, gets treated the same as before, yeilding T1 as the cipher. 
Now this cipher is XORed with E, the next block. 
But, T1 xor E ==> T1 xor T1 xor A => A
Hence the Tag from the second encryption function is Tag = Encryption(E xor T1, key)  = Encryption(A, key) = T1
Thus, the tag is predicable.
```

The full solution is provided here:

```
from pwn import *
from binascii import *

B = b'B'*16

def getTag(p, msg):
    p.recvuntil(b'Choice: ')
    p.sendline(b'1')
    p.recvuntil(b'msg (hex): ')

    hexed_msg = hexlify(msg)
    p.send(hexed_msg)

    p.recvuntil(b'(msg):')
    tag = p.recvline().strip()
    print(f"{msg =}\nX:{tag= }")

    return unhexlify(tag)

def forgeMessage(p, msg, tag):
    p.recvuntil(b'Choice: ')
    p.sendline(b'2')
    p.recvuntil(b'msg (hex): ')
    p.send(hexlify(msg))
    p.recvuntil(b'tag (hex): ')
    p.send(hexlify(tag))

p = remote('0.0.0.0', 60001)
t1 = getTag(p, B)
E = xor(B, t1)
forgeMessage(p, B + E, t1)

p.interactive()
```
