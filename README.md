![image](https://github.com/nour-lx/Elliptic-curve-cryptography/assets/139453481/36d9e9f7-1594-4425-920f-b03c13b8e7b2)Elliptic Curve Cryptosystem in Python!

The elliptic curve cryptography (ECC) does not directly provide encryption method 
Instead, we can design a hybrid encryption scheme by using the ECDH (Elliptic Curve Diffie–Hellman) key exchange scheme to derive a shared secret key for symmetric data encryption and decryption.
AES Encryption Algorithm with 256-bit Key is used
AES is a block cipher.
Encrypts data in blocks of 128 bits each

What we need :
Some python libraries
Eliptic Curve Domain Parameters :
The prime p that specifies the size of the finite field
The coefficients a and b of the elliptic curve equation.
The base point G that generates our subgroup.
The order n of the subgroup.
The cofactor h of the subgroup.
