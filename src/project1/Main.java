package project1;

import java.util.Arrays;

public class Main {

    public static void main(String[] args) {
        System.out.println("-------- QUESTION 1 --------");
        System.out.println("Raw Key\t\tPlaintext\tCiphertext");

        byte[] rawkey0 = {0,0,0,0,0,0,0,0,0,0};
        byte[] plaintext0 = {0,0,0,0,0,0,0,0};
        print_SDES_cyphertext(rawkey0, plaintext0);

        byte[] rawkey1 = {1,1,1,1,1,1,1,1,1,1};
        byte[] plaintext1 = {1,1,1,1,1,1,1,1};
        print_SDES_cyphertext(rawkey1, plaintext1);

        byte[] rawkey2 = {0,0,0,0,0,1,1,1,1,1};
        // plaintext0 = 00000000
        print_SDES_cyphertext(rawkey2, plaintext0);

        // rawkey2 = 0000011111
        // plaintext1 = 11111111
        print_SDES_cyphertext(rawkey2, plaintext1);

        byte[] rawkey3 = {1,0,0,0,1,0,1,1,1,0};
        byte[] cyphertext0 = {0,0,0,1,1,1,0,0};
        print_SDES_plaintext(rawkey3, cyphertext0);

        // rawkey3 = 1000101110
        byte[] cyphertext1 = {1,1,0,0,0,0,1,0};
        print_SDES_plaintext(rawkey3, cyphertext1);

        byte[] rawkey4 = {0,0,1,0,0,1,1,1,1,1};
        byte[] cyphertext2 = {1,0,0,1,1,1,0,1};
        print_SDES_plaintext(rawkey4, cyphertext2);

        // rawkey4 = 11000010
        byte[] cyphertext3 = {1,0,0,1,0,0,0,0};
        print_SDES_plaintext(rawkey4, cyphertext3);

        System.out.println("\n-------- QUESTION 2 --------");
        System.out.println("Raw Key 1\tRaw Key 2\tPlaintext\tCiphertext");

        // raw key0 = 0000000000
        // plaintext0 = 00000000
        print_TripleSDES_cyphertext(rawkey0, rawkey0, plaintext0);

        // raw key3 = 1000101110
        byte[] rawkey6 = {0,1,1,0,1,0,1,1,1,0};
        byte[] plaintext2 = {1,1,0,1,0,1,1,1};
        print_TripleSDES_cyphertext(rawkey3, rawkey6, plaintext2);

        // raw key3 = 1000101110
        // raw key6 = 0110101110
        byte[] plaintext3 = {1,0,1,0,1,0,1,0};
        print_TripleSDES_cyphertext(rawkey3, rawkey6, plaintext3);

        // raw key1 = 1111111111
        // plaintext3 = 10101010
        print_TripleSDES_cyphertext(rawkey1, rawkey1, plaintext3);

        // raw key3 = 1000101110
        // raw key6 = 0110101110
        byte[] cyphertext4 = {1,1,1,0,0,1,1,0};
        print_TripleSDES_plaintext(rawkey3, rawkey6, cyphertext4);

        byte[] rawkey5 = {1,0,1,1,1,0,1,1,1,1};
        // raw key6 = 0110101110
        byte[] cyphertext5 = {0,1,0,1,0,0,0,0};
        print_TripleSDES_plaintext(rawkey5, rawkey6, cyphertext5);

        // raw key0 = 0000000000
        byte[] cyphertext6 = {1,0,0,0,0,0,0,0};
        print_TripleSDES_plaintext(rawkey0, rawkey0, cyphertext6);

        // raw key1 = 1111111111
        byte[] cyphertext7 = {1,0,0,1,0,0,1,0};
        print_TripleSDES_plaintext(rawkey1, rawkey1, cyphertext7);

        System.out.println("\n-------- QUESTION 3 --------");

        String ascii_text = "CRYPTOGRAPHY";
        byte[] cascii_bytes = CASCII.Convert(ascii_text);
        byte[] rawkey_cascii = {0,1,1,1,0,0,1,1,0,1};
        byte[] cascii_cyhertext = SDES.encrypt_message(rawkey_cascii, cascii_bytes);
        System.out.println("1.) " + format_bytes(cascii_cyhertext));

        String cascii_string_sdes = "1011011001111001001011101111110000111110100000000001110111010001111011111101101100010011000000101101011010101000101111100011101011010111100011101001010111101100101110000010010101110001110111011111010101010100001100011000011010101111011111010011110111001001011100101101001000011011111011000010010001011101100011011110000000110010111111010000011100011111111000010111010100001100001010011001010101010000110101101111111010010110001001000001111000000011110000011110110010010101010100001000011010000100011010101100000010111000000010101110100001000111010010010101110111010010111100011111010101111011101111000101001010001101100101100111001110111001100101100011111001100000110100001001100010000100011100000000001001010011101011100101000111011100010001111101011111100000010111110101010000000100110110111111000000111110111010100110000010110000111010001111000101011111101011101101010010100010111100011100000001010101110111111101101100101010011100111011110101011011";
        byte[] found_key1 = Cracking.bruteforce_sdes(cascii_string_sdes);
        System.out.println("2.) " + format_bytes(found_key1));
        byte[] cascii_plaintext = SDES.decrypt_message(found_key1, Cracking.get_bytes(cascii_string_sdes));
        System.out.println(CASCII.toString(cascii_plaintext));

        String cascii_string_triplesdes = "00011111100111111110011111101100111000000011001011110010101010110001011101001101000000110011010111111110000000001010111111000001010010111001111001010101100000110111100011111101011100100100010101000011001100101000000101111011000010011010111100010001001000100001111100100000001000000001101101000000001010111010000001000010011100101111001101111011001001010001100010100000";
        byte[] testkey1 = {0,0,0,0,0,0,0,0,0,0};
        byte[] testkey2 = {0,0,0,0,0,0,0,0,0,0};
        Cracking.bruteforce_tsdes(cascii_string_triplesdes, testkey1, testkey2);
        System.out.println("3.) " + format_bytes(testkey1) + " " + format_bytes(testkey2));
        cascii_plaintext = TripleSDES.decrypt_message(testkey1, testkey2, Cracking.get_bytes(cascii_string_triplesdes));
        System.out.println(CASCII.toString(cascii_plaintext));
    }

    private static void print_SDES_cyphertext(byte[] rawkey, byte[] plaintext) {
        System.out.println(
                format_bytes(rawkey) + "\t" +
                format_bytes(plaintext) + "\t" +
                format_bytes(SDES.Encrypt(rawkey, plaintext)));
    }

    private static void print_SDES_plaintext(byte[] rawkey, byte[] cyphertext) {
        System.out.println(
                format_bytes(rawkey) + "\t" +
                format_bytes(SDES.Decrypt(rawkey, cyphertext)) + "\t" +
                format_bytes(cyphertext));
    }

    private  static void print_TripleSDES_cyphertext(byte[] rawkey1, byte[] rawkey2, byte[] plaintext) {
        System.out.println(
                format_bytes(rawkey1) + "\t" +
                format_bytes(rawkey2) + "\t" +
                format_bytes(plaintext) + "\t" +
                format_bytes(TripleSDES.Encrypt(rawkey1, rawkey2, plaintext)));
    }

    private  static void print_TripleSDES_plaintext(byte[] rawkey1, byte[] rawkey2, byte[] cyphertext) {
        System.out.println(
                format_bytes(rawkey1) + "\t" +
                format_bytes(rawkey2) + "\t" +
                format_bytes(TripleSDES.Decrypt(rawkey1, rawkey2, cyphertext)) + "\t" +
                format_bytes(cyphertext));
    }

    public static String format_bytes(byte[] bytes) {
        return Arrays.toString(bytes)
                .replace(", ", "")
                .replace("[", "")
                .replace("]", "");
    }
}