package project1;

public class SDES {
    public static byte[] Encrypt(byte[] rawkey, byte[] plaintext) {
        byte[] k1 = new byte[8];
        byte[] k2 = new byte[8];
        key_generation(rawkey, k1, k2);

        // initial permutation
        int[] ip8 = {1, 5, 2, 0, 3, 7, 4, 6};
        byte[] ip_output = get_permutation(plaintext, ip8);

        // first fk function pass
        byte[] round1_output = encryption_round(ip_output, k1);

        // SW
        int[] swap_table = {4, 5, 6, 7, 0, 1, 2, 3};
        byte[] swapped_round1_output = get_permutation(round1_output, swap_table);

        // second fk function pass
        byte[] round2_output = encryption_round(swapped_round1_output, k2);

        // inverse ip
        int[] ip8_inverse = {3, 0, 2, 4, 6, 1, 7, 5};

        return get_permutation(round2_output, ip8_inverse);
    }

    public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext) {
        byte[] k1 = new byte[8];
        byte[] k2 = new byte[8];
        key_generation(rawkey, k1, k2);

        // initial permutation
        int[] ip8 = {1, 5, 2, 0, 3, 7, 4, 6};
        byte[] ip_output = get_permutation(ciphertext, ip8);

        // first fk function pass
        byte[] round1_output = encryption_round(ip_output, k2);

        // SW
        int[] swap_table = {4, 5, 6, 7, 0, 1, 2, 3};
        byte[] swapped_round1_output = get_permutation(round1_output, swap_table);

        // second fk function pass
        byte[] round2_output = encryption_round(swapped_round1_output, k1);

        // inverse ip
        int[] ip8_inverse = {3, 0, 2, 4, 6, 1, 7, 5};

        return get_permutation(round2_output, ip8_inverse);
    }

    public static byte[] encrypt_message(byte[] rawkey, byte[] message) {
        byte[] cyphertext = new byte[message.length];

        for (int i = 0; i < message.length; i += 8) {
            byte[] plaintext_block = new byte[8];
            System.arraycopy(message, i, plaintext_block, 0, 8);

            byte[] cyphertext_block = SDES.Encrypt(rawkey, plaintext_block);
            System.arraycopy(cyphertext_block, 0, cyphertext, i, 8);
        }

        return cyphertext;
    }

    public static byte[] decrypt_message(byte[] rawkey, byte[] message) {
        byte[] plaintext = new byte[message.length];

        for (int i = 0; i < message.length; i += 8) {
            byte[] cyphertext_block = new byte[8];
            System.arraycopy(message, i, cyphertext_block, 0, 8);

            byte[] plaintext_block = Decrypt(rawkey, cyphertext_block);
            System.arraycopy(plaintext_block, 0, plaintext, i, 8);
        }

        return plaintext;
    }

    public static void key_generation(byte[] rawkey, byte[] k1, byte[] k2) {
        // --- FIRST KEY GENERATION ---
        // p10 permutation
        int[] p10 = {2, 4, 1, 6, 3, 9, 0, 8, 7, 5};
        byte[] p10_output = get_permutation(rawkey, p10);

        // spit key into halves
        byte[] key_left_half = new byte[5];
        byte[] key_right_half = new byte[5];
        split_bytes(p10_output, key_left_half, key_right_half);

        // apply round shift on each halve
        key_left_half = round_shift(key_left_half);
        key_right_half = round_shift(key_right_half);

        // combine halves
        byte[] shifted_key = combine_bytes(key_left_half, key_right_half);

        // p8 permutation
        int[] p8 = {5, 2, 6, 3, 7, 4, 9, 8};
        for (int i = 0; i < p8.length; i++) {
            k1[i] = shifted_key[p8[i]];
        }

        // --- SECOND KEY GENERATION ---
        // apply two round shifts on each halve
        key_left_half = round_shift(key_left_half);
        key_left_half = round_shift(key_left_half);
        key_right_half = round_shift(key_right_half);
        key_right_half = round_shift(key_right_half);

        // combine halves
        byte[] shifted_key2 = combine_bytes(key_left_half, key_right_half);

        // p8 permutation
        for (int i = 0; i < p8.length; i++) {
            k2[i] = shifted_key2[p8[i]];
        }
    }

    private static byte[] encryption_round(byte[] input, byte[] key) {
        // split text into halves
        byte[] input_left_half = new byte[4];
        byte[] input_right_half = new byte[4];
        split_bytes(input, input_left_half, input_right_half);

        // expand and per-mutate right half
        int[] ep = {3, 0, 1, 2, 1, 2, 3, 0};
        byte[] ep_output = get_permutation(input_right_half, ep);

        // XOR expanded output and first key
        byte[] xor_output1 = xor_bytes(ep_output, key);

        // split xor_output into halves
        byte[] xor_left_half = new byte[4];
        byte[] xor_right_half = new byte[4];
        split_bytes(xor_output1, xor_left_half, xor_right_half);

        // put into s boxes
        byte[] s0 = {
                1, 0, 3, 2,
                3, 2, 1, 0,
                0, 2, 1, 3,
                3, 1, 3, 2};

        byte[] s1 = {
                0, 1, 2, 3,
                2, 0, 1, 3,
                3, 0, 1, 0,
                2, 1, 0, 3};

        byte[] left_sbox_output = get_sbox_output(xor_left_half, s0);
        byte[] right_sbox_output = get_sbox_output(xor_right_half, s1);

        // combine sbox outputs
        byte[] sbox_output = combine_bytes(left_sbox_output, right_sbox_output);

        // p4 permutation
        int[] p4 = {1, 3, 2, 0};
        byte[] p4_output = get_permutation(sbox_output, p4);

        // XOR p4output with left 4bits of initial permutation
        byte[] xor_output2 = xor_bytes(input_left_half, p4_output);

        // combine xor output with right half of initial permutation

        return combine_bytes(xor_output2, input_right_half);
    }

    private static byte[] get_permutation(byte[] input, int[] ptable) {
        byte[] output = new byte[ptable.length];

        for (int i = 0; i < ptable.length; i++) {
            output[i] = input[ptable[i]];
        }

        return output;
    }

    private static void split_bytes(byte[] input, byte[] left_half, byte[] right_half) {
        for (int i = 0; i < input.length; i++) {
            if (i < left_half.length) {
                left_half[i] = input[i];
            } else {
                right_half[i - left_half.length] = input[i];
            }
        }
    }

    private static byte[] combine_bytes(byte[] left_half, byte[] right_half) {
        byte[] output = new byte[left_half.length * 2];

        for (int i = 0; i < output.length; i++) {
            if (i < left_half.length) {
                output[i] = left_half[i];
            } else {
                output[i] = right_half[i - left_half.length];
            }
        }

        return output;
    }

    private static byte[] round_shift(byte[] input) {
        byte[] output = new byte[input.length];

        for (int i = 0; i < input.length; i++) {
            if (i == 0) {
                output[input.length - 1] = input[i];
            } else {
                output[i - 1] = input[i];
            }
        }

        return output;
    }

    private static byte[] xor_bytes(byte[] a, byte[] b) {
        byte[] output = new byte[a.length];

        for (int i = 0; i < a.length; i++) {
            if (a[i] + b[i] == 1) {
                output[i] = 1;
            } else {
                output[i] = 0;
            }
        }

        return output;
    }

    private static byte[] get_sbox_output(byte[] input, byte[] sbox) {
        int row, col, sbox_num;
        byte[] output = new byte[2];

        row = input[0] * 2 + input[3];
        col = input[1] * 2 + input[2];

        sbox_num = sbox[row * 4 + col];

        if (sbox_num == 1) {
            output[1] = 1;
        } else if (sbox_num == 2) {
            output[0] = 1;
        } else if (sbox_num == 3) {
            output[0] = 1;
            output[1] = 1;
        }

        return output;
    }
}
