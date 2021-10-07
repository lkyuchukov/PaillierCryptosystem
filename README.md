PaillierCryptoSystem
-
Paillier cryptosystem, implemented in Java. 

The Paillier cryptosystem, invented by Pascal Paillier in 1999, is a partial homomorphic encryption scheme which allows two types of computation on encrypted data:
- addition of two ciphertexts
- multiplication of a ciphertext by a plaintext number

Homomorphic Addition
----------------
```java
BigInteger plainA = BigInteger.valueOf(102);
BigInteger plainB = BigInteger.valueOf(203);

BigInteger encryptedA = paillierCryptoSystem.encrypt(plainA);
BigInteger encryptedB = paillierCryptoSystem.encrypt(plainB);

BigInteger encryptedSum = paillierCryptoSystem.add(encryptedA, encryptedB);
BigInteger plainSum = plainA.add(plainB).mod(paillierCryptoSystem.getN());

paillierCryptoSystem.decrypt(encryptedSum) == plainSum // true
```

Homomorphic Multiplication With Constant
----------------
```java
BigInteger plainA = BigInteger.valueOf(14);
BigInteger plainB = BigInteger.valueOf(203);

BigInteger encryptedA = paillierCryptoSystem.encrypt(plainA);

BigInteger encryptedProduct = paillierCryptoSystem.multiplyWithConstant(encryptedA, plainB);
BigInteger plainProduct = plainA.multiply(plainB).mod(paillierCryptoSystem.getN());

paillierCryptoSystem.decrypt(encryptedProduct) == plainProduct // true
```

References
---------------
https://en.wikipedia.org/wiki/Paillier_cryptosystem
