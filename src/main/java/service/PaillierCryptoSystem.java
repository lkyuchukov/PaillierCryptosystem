package service;

import paillier.encryption.KeyPair;
import paillier.encryption.KeyPairGenerator;
import paillier.encryption.PublicKey;

import java.math.BigInteger;

/**
 * Party homomorphic encryption system.
 */
public class PaillierCryptoSystem {

    private KeyPair keyPair;
    private PublicKey publicKey;

    public PaillierCryptoSystem() {
        keyPair = new KeyPairGenerator().generateKeyPair();
        publicKey = keyPair.getPublicKey();

    }

    public BigInteger encrypt(BigInteger input) {
        return publicKey.encrypt(input);
    }

    public BigInteger decrypt(BigInteger encryptedData) {
        return keyPair.decrypt(encryptedData);
    }

    /**
     * When two ciphertexts are multiplied, the result decrypts to the sum of their plaintexts.
     * @param encryptedA First Ciphertext
     * @param encryptedB Second Ciphertext
     * @return The sum of the plaintext values of the encrypted numbers.
     */
    public BigInteger add(BigInteger encryptedA, BigInteger encryptedB) {
        return encryptedA.multiply(encryptedB).mod(publicKey.getNSquared());
    }

    /**
     * When a ciphertext is raised to the power of a plaintext, the result decrypts to the product of the two plaintexts.
     * @param encryptedValue Ciphertext
     * @param constant Constant value
     * @return the product of the two plaintexts
     */
    public BigInteger multiplyWithConstant(BigInteger encryptedValue, BigInteger constant) {
        if (constant.compareTo(BigInteger.ZERO) == 0) {
            /**
             * Any number to the power of 0 is 1 and if we multiply a ciphertext by a plaintext 0 using the method above,
             * the result will always be 1, and anyone who sees this "encrypted" value will know that it decrypts to 0.
             *
             * Because of the random number in the encryption step we can just encrypt 0 and return it.
             */
            return encrypt(BigInteger.ZERO);
        } else if (constant.compareTo(BigInteger.ONE) == 0) {
            /**
             *  If we multiply a ciphertext by a plaintext 1 using the normal method,
             *  the output will be the same as the input.
             *
             *  The workaround is to freshly encrypt a zero and add the two ciphers together
             */
            return add(encryptedValue, encrypt(BigInteger.ZERO));
        } else {
            return encryptedValue.modPow(constant, publicKey.getNSquared());
        }

    }

    public BigInteger getN() {
        return publicKey.getN();
    }

}
