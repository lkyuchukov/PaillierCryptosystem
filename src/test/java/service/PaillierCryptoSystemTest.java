package service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class PaillierCryptoSystemTest {

    private PaillierCryptoSystem paillierCryptoSystem;

    @BeforeEach
    void setUp() {
        paillierCryptoSystem = new PaillierCryptoSystem(Long.MAX_VALUE);
    }

    @Test
    void decrypt() {
        BigInteger encryptedData = paillierCryptoSystem.encrypt(BigInteger.valueOf(10));

        assertEquals(BigInteger.valueOf(10), paillierCryptoSystem.decrypt(encryptedData));
    }

    @Test
    void homomorphicAddition() {
        BigInteger plainA = BigInteger.valueOf(102);
        BigInteger plainB = BigInteger.valueOf(203);

        BigInteger encryptedA = paillierCryptoSystem.encrypt(plainA);
        BigInteger encryptedB = paillierCryptoSystem.encrypt(plainB);

        BigInteger encryptedSum = paillierCryptoSystem.add(encryptedA, encryptedB);
        BigInteger plainSum = plainA.add(plainB).mod(paillierCryptoSystem.getN());

        assertEquals(paillierCryptoSystem.decrypt(encryptedSum), plainSum);
    }

    @Test
    public void homomorphicConstantMultiplication() {
        BigInteger plainA = BigInteger.valueOf(14);
        BigInteger plainB = BigInteger.valueOf(203);

        BigInteger encryptedA = paillierCryptoSystem.encrypt(plainA);

        BigInteger encryptedProduct = paillierCryptoSystem.multiplyWithConstant(encryptedA, plainB);
        BigInteger plainProduct = plainA.multiply(plainB).mod(paillierCryptoSystem.getN());

        assertEquals(paillierCryptoSystem.decrypt(encryptedProduct), plainProduct);
    }

    @Test
    public void homomorphicConstantMultiplicationWith0() {
        BigInteger plainA = BigInteger.valueOf(15);

        BigInteger encryptedA = paillierCryptoSystem.encrypt(plainA);

        BigInteger encryptedProduct = paillierCryptoSystem.multiplyWithConstant(encryptedA, BigInteger.ZERO);
        BigInteger plainProduct = plainA.multiply(BigInteger.ZERO).mod(paillierCryptoSystem.getN());

        assertNotEquals(encryptedProduct, plainA);
        assertEquals(paillierCryptoSystem.decrypt(encryptedProduct), plainProduct);
    }

    @Test
    public void homomorphicConstantMultiplicationWith1() {
        BigInteger plainA = BigInteger.valueOf(16);

        BigInteger encryptedA = paillierCryptoSystem.encrypt(plainA);

        BigInteger encryptedProduct = paillierCryptoSystem.multiplyWithConstant(encryptedA, BigInteger.ONE);
        BigInteger plainProduct = plainA.multiply(BigInteger.ONE).mod(paillierCryptoSystem.getN());

        assertNotEquals(encryptedProduct, plainA);
        assertEquals(paillierCryptoSystem.decrypt(encryptedProduct), plainProduct);
    }

}