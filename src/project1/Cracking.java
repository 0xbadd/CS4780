package project1;

public class Cracking {
    static public byte[] bruteforce_sdes(String message) {
        byte[] cascii_encrypted_message1 = get_bytes(message);
        byte[] testkey = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        for (int i = 0; i < 1024; i++) {
            byte[] cascii_plaintext = SDES.decrypt_message(testkey, cascii_encrypted_message1);
            String plaintext = CASCII.toString(cascii_plaintext);

            if (plaintext.toLowerCase().contains("crypto")) {
                return testkey;
            } else {
                get_new_key(testkey, i);
            }
        }

        return testkey;
    }

    static public void bruteforce_tsdes(String message, byte[] testkey1, byte[] testkey2) {
        byte[] cascii_encrypted_message1 = get_bytes(message);

        for (int i = 0; i < 1024; i++) {
            for (int j = 0; j < 1024; j++) {
                byte[] cascii_plaintext = TripleSDES.decrypt_message(testkey1, testkey2, cascii_encrypted_message1);
                String plaintext = CASCII.toString(cascii_plaintext);

                if (plaintext.toLowerCase().contains("byte")) {
                    return;
                } else {
                    get_new_key(testkey2, j);
                }
            }
            get_new_key(testkey1, i);
        }
    }

    public static byte[] get_bytes(String message) {
        char[] char_message = new char[message.length()];

        for (int i = 0; i < message.length(); i++) {
            char_message[i] = message.charAt(i);
        }

        byte[] output = new byte[message.length()];
        for (int i = 0; i < char_message.length; i++) {
            if (char_message[i] == '0') {
                output[i] = 0;
            } else {
                output[i] = 1;
            }
        }

        return output;
    }

    private static void get_new_key(byte[] oldkey, int index) {
        String newkey_string = Integer.toBinaryString(index);
        if (newkey_string.length() < 10) {
            int padding_size = 10 - newkey_string.length();
            char[] char_padding = new char[padding_size];
            for (int i = 0; i < padding_size; i++) {
                char_padding[i] = '0';
            }
            newkey_string = new String(char_padding).concat(newkey_string);
        }
        byte[] newkey = get_bytes(newkey_string);
        System.arraycopy(newkey, 0, oldkey, 0, oldkey.length);
    }
}
