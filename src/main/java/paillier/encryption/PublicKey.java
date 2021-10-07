package paillier.encryption;

import java.math.BigInteger;
import java.util.Random;

/**
 * A class that represents the public part of the Paillier key pair. Responsible for the encryption.
 */
public class PublicKey {

    private final int bits;
    private final BigInteger n;
    private final BigInteger nSquared;
    private final BigInteger g;

    public PublicKey(BigInteger n,
                     BigInteger nSquared,
                     BigInteger g,
                     int bits) {
        this.n = n;
        this.nSquared = nSquared;
        this.bits = bits;
        this.g = g;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getNSquared() {
        return nSquared;
    }

    /**
     * Encrypts the given plaintext.
     *
     * @param m The plaintext that should be encrypted.
     * @return The corresponding ciphertext.
     */
    public BigInteger encrypt(BigInteger m) {

        // pick a random number in the range 0 < r and r < n
        BigInteger r;
        do {
            r = new BigInteger(bits, new Random());
        } while (r.compareTo(n) >= 0);

        // compute the ciphertext
        BigInteger result = g.modPow(m, nSquared);
        BigInteger x = r.modPow(n, nSquared);

        result = result.multiply(x);
        result = result.mod(nSquared);

        return result;
    }
}
