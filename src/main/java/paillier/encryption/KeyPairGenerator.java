package paillier.encryption;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 * A class that is used for generating a pair of associated public and private
 * keys.
 *
 * @see KeyPair
 */
public class KeyPairGenerator {

    private int bits = 1024;

    private int certainty = 0;

    private Random rng = new SecureRandom();

    private BigInteger upperBound = BigInteger.valueOf(Long.MAX_VALUE);

    /**
     * Creates a pair of associated public and private keys.
     *
     * @return The pair of associated public and private keys.
     */
    public KeyPair generateKeyPair() {
        // pick two large prime numbers randomly and independently
        BigInteger p, q;
        int length = bits / 2;
        if (certainty > 0) {
            p = new BigInteger(length, certainty, rng);
            q = new BigInteger(length, certainty, rng);
        } else {
            p = BigInteger.probablePrime(length, rng);
            q = BigInteger.probablePrime(length, rng);
        }

        BigInteger n = p.multiply(q);
        BigInteger nSquared = n.multiply(n);

        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        BigInteger qMinusOne = q.subtract(BigInteger.ONE);

        BigInteger lambda = this.lcm(pMinusOne, qMinusOne);

        BigInteger g;
        BigInteger helper;

        do {
            g = new BigInteger(bits, rng);
            helper = calculateL(g.modPow(lambda, nSquared), n);

        } while (!helper.gcd(n).equals(BigInteger.ONE));

        PublicKey publicKey = new PublicKey(n, nSquared, g, bits);
        PrivateKey privateKey = new PrivateKey(lambda, helper.modInverse(n));

        return new KeyPair(privateKey, publicKey, upperBound);

    }

    private BigInteger calculateL(BigInteger u, BigInteger n) {
        BigInteger result = u.subtract(BigInteger.ONE);
        result = result.divide(n);
        return result;
    }

    private BigInteger lcm(BigInteger a, BigInteger b) {
        BigInteger result;
        BigInteger gcd = a.gcd(b);

        result = a.abs().divide(gcd);
        result = result.multiply(b.abs());

        return result;
    }
}
