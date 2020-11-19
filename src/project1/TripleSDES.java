package project1;

public class TripleSDES {
    public static byte[] Encrypt(byte[] rawkey1, byte[] rawkey2, byte[] plaintext) {
        return SDES.Encrypt(rawkey1, SDES.Decrypt(rawkey2, SDES.Encrypt(rawkey1, plaintext)));
    }

    public static byte[] Decrypt(byte[] rawkey1, byte[] rawkey2, byte[] ciphertext) {
        return SDES.Decrypt(rawkey1, SDES.Encrypt(rawkey2, SDES.Decrypt(rawkey1, ciphertext)));
    }

    public static byte[] decrypt_message(byte[] rawkey1, byte[] rawkey2, byte[] message) {
        byte[] plaintext = new byte[message.length];

        for (int i = 0; i < message.length; i += 8) {
            byte[] cyphertext_block = new byte[8];
            System.arraycopy(message, i, cyphertext_block, 0, 8);

            byte[] plaintext_block = Decrypt(rawkey1, rawkey2, cyphertext_block);
            System.arraycopy(plaintext_block, 0, plaintext, i, 8);
        }

        return plaintext;
    }
}
