---
title: RSA Algorithm
published: true
---


### [](#header-3)What is the RSA algorithm?
RSA (Rivest-Shamir-Adleman) is an asymmetric encryption algorithm often used in situations such as internet traffic and VPN networks. The RSA algorithm relies on the difficulty of factoring the product of large prime numbers. This feature ensures the security of RSA. Linux users like me know that ssh services use rsa key pairs.

### [](#header-3)How does it work?
First, two large prime numbers ```p``` and ```q``` are chosen. These two prime numbers are multiplied and ```n = p*q``` is calculated. The number ```n``` is used as the module for encryption. Then, ```φ(n) = (p-1)*(q-1)``` is calculated. The ```φ``` function is known as Euler's Totient function and finds the number of positive integers less than ```n``` and prime to ```n```. Also shown as ```phi```. A number e is chosen such that ```1 < e < φ(n)```. This number ```e``` and ```φ(n)``` must be a prime number with each other. The number e is usually chosen as a small prime number like 65537 and used as the "public key". The ```d``` value is found, which satisfies the equation ```d * e ≡ 1 (mod φ(n))```. This ```d``` number is used as the "private key".

Encryption and decryption are done as follows:
To encrypt, take the message ```m``` and calculate ```c = m^e mod(n)```. where ```c``` is the encrypted message.
To decrypt, take the encrypted message ```c``` and calculate ```m = c^d mod(n)```. where ```m``` is the original message.

With this method, the public key ```(e, n)``` can be known to everyone and messages can be encrypted with this key. However, only the person who knows the private key ```(d)``` has the ability to decode these messages.

### [](#header-3)Any script?
This script can make your job easier when using the rsa algorithm. Remember that you need to edit.
```
# For RSA

import binascii
from Crypto.Util.number import inverse, long_to_bytes

with open('flag.enc') as handle:
    c = handle.read()

print(int(binascii.hexlify(c),16))

p = 123
q = 123

n = p * q
phi = (p - 1) * (q - 1)

e = 667

d = inverse(e, phi)
m = pow(c,d,n)

print(binascii.unhexlify('0'+hex(m)[2:-1]))
# print(hex(pow(c, d, N))[2:-1].decode('hex'))


text = "alper"
number = int(binascii.hexlify(text.encode()), 16) 
binascii.unhexlify(hex(number)[2:]).decode()
```

### [](#header-3)What is the PEM file?
PEM (Privacy Enhanced Mail) files are a type of file format commonly used in SSL certificates and RSA and DSA key pairs. These files usually contain one or more public keys, private keys, or certificates. You can store your RSA private key in a PEM file. It is important that you keep this file secure, because anyone holding this key can decrypt data encrypted with this key. You can create your own private and public pem files and encrypt your message with the commands below.

```
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private_key.pem -out public_key.pem
openssl pkeyutl -encrypt -pubin -inkey public_key.pem -in plain_text.txt -out encrypted_text.txt
openssl pkeyutl -decrypt -inkey private_key.pem -in encrypted_text.txt -out decrypted_text.txt
```


