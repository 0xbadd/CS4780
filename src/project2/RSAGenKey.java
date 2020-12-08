package project2;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Random;

public class RSAGenKey {
    private BigInteger P;
    private BigInteger Q;
    private BigInteger N;
    private BigInteger PHI;
    private BigInteger e;
    private BigInteger d;
    private int maxLength = 1024;
    private Random R = new Random();

    public RSAGenKey(int k) {
        generatePrimeNumbers(k);
        generatePublicPrivateKeys();
    }

    public RSAGenKey(BigInteger p, BigInteger q, BigInteger e) {
        this.P = p;
        this.Q = q;
        this.e = e;
        generatePublicPrivateKeys(e);
    }

    private void generatePrimeNumbers(int k) {
        maxLength = k;
        P = BigInteger.probablePrime(maxLength, R);
        Q = BigInteger.probablePrime(maxLength, R);
    }

    private void generatePublicPrivateKeys() {
        N = P.multiply(Q);
        PHI = P.subtract(BigInteger.ONE).multiply(Q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(maxLength / 2, R);
        while (PHI.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(PHI) < 0) {
            e.add(BigInteger.ONE);
        }
        d = e.modInverse(PHI);
    }

    private void generatePublicPrivateKeys(BigInteger e) {
        N = P.multiply(Q);
        PHI = P.subtract(BigInteger.ONE).multiply(Q.subtract(BigInteger.ONE));
        while (PHI.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(PHI) < 0) {
            e.add(BigInteger.ONE);
        }
        d = e.modInverse(PHI);
    }

    public static void main(String[] args) {
        RSAGenKey rsa = new RSAGenKey(1024);
        if (args.length == 1) {
            int k = Integer.parseInt(args[0]);
            rsa = new RSAGenKey(k);
        } else if (args.length == 3) {
            BigInteger p = new BigInteger(args[0]);
            BigInteger q = new BigInteger(args[1]);
            BigInteger e = new BigInteger(args[2]);
            rsa = new RSAGenKey(p, q, e);
        } else {
            System.out.println("Usage:");
            System.out.println("java RSAGenKey k");
            System.out.println();
            System.out.println("java RSAGenKey p q e");
            return;
        }
        try {
            FileWriter fileWriter = new FileWriter("pub_key.txt");
            PrintWriter printWriter = new PrintWriter(fileWriter);
            printWriter.println("e = " + rsa.e);
            printWriter.println("n = " + rsa.N);
            printWriter.close();

            fileWriter = new FileWriter("pri_key.txt");
            printWriter = new PrintWriter(fileWriter);
            printWriter.println("d = " + rsa.d);
            printWriter.println("n = " + rsa.N);
            printWriter.close();

            System.out.println("Successfully wrote to the files.");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }
}
