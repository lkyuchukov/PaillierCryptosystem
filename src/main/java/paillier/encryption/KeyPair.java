package paillier.encryption;

import java.math.BigInteger;

/**
 * A class that holds a pair of associated public and private keys.
 */
public class KeyPair {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final BigInteger upperBound;

    public KeyPair(PrivateKey privateKey,
                   PublicKey publicKey,
                   BigInteger upperBound) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.upperBound = upperBound;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Decrypts the given ciphertext.
     *
     * @param c The ciphertext that should be decrypted.
     * @return The corresponding plaintext.
     */
    public final BigInteger decrypt(BigInteger c) {
        BigInteger n = publicKey.getN();
        BigInteger nSquared = publicKey.getNSquared();
        BigInteger lambda = privateKey.getLambda();

        BigInteger u = privateKey.getPreCalculatedDenominator();

        BigInteger m = c.modPow(lambda, nSquared).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);

        if (upperBound != null && m.compareTo(upperBound) > 0) {
            m = m.subtract(n);
        }

        return m;
    }
}
