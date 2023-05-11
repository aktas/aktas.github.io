---
title: RSA Algorithm
published: true
---

### [](#header-3)What is the RSA algorithm?
RSA (Rivest-Shamir-Adleman) is an asymmetric encryption algorithm often used in situations such as internet traffic and VPN networks. The RSA algorithm relies on the difficulty of factoring the product of large prime numbers. This feature ensures the security of RSA. Linux users like me know that ssh services use rsa key pairs.

### [](#header-3)How does it work?
First, two large prime numbers p and q are chosen. These two prime numbers are multiplied and n = p*q is calculated. The number n is used as the module for encryption. Then, φ(n) = (p-1)*(q-1) is calculated. φ function, Euler's Totient
It is known as a function and finds the number of positive integers less than n and prime to n. Also shown as phi. A number e is chosen such that 1 < e < φ(n). This number e and φ(n) must be a prime number with each other. The number e is usually chosen as a small prime number like 65537 and used as the "public key". The d value is found, which satisfies the equation d * e ≡ 1 (mod φ(n)). This d number is used as the "private key".
