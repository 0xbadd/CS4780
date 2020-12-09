package project2;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;

public class RSADecrypt {
    public static void main(String[] args) {
        String encryptedMessage = "";
        try {
            Path filename = Path.of(args[0]);
            encryptedMessage = Files.readString(filename);
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        // Read private key text
        BigInteger D = BigInteger.ZERO;
        BigInteger N = BigInteger.ZERO;
        try {
            File myObj = new File(args[1]);
            Scanner myReader = new Scanner(myObj);

            String pub_d = myReader.nextLine();
            String pub_n = myReader.nextLine();

            D = new BigInteger(pub_d.split(" ")[2]);
            N = new BigInteger(pub_n.split(" ")[2]);

            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        // split cipher into blocks
        String[] encryptedBlocks = encryptedMessage.split(" ");

        StringBuilder plaintextMessage = new StringBuilder();
        for (String block : encryptedBlocks) {
            // Decrypt block
            BigInteger plaintextBlock = new BigInteger(block).modPow(D, N);

            // Pad the block with zeros if necessary
            String plaintextBlockStr = plaintextBlock.toString();
            if (plaintextBlockStr.length() < 6) {
                int diff = 6 - plaintextBlockStr.length();
                plaintextBlockStr = "0".repeat(Math.max(0, diff)) + plaintextBlockStr;
            }

            // Encode message block
            StringBuilder decodedBlock = new StringBuilder();
            while (plaintextBlockStr.length() > 0) {
                int num;
                if (plaintextBlockStr.length() > 2) {
                    num = Integer.parseInt(plaintextBlockStr.substring(0, 2));
                    plaintextBlockStr = plaintextBlockStr.substring(2);
                } else {
                    num = Integer.parseInt(plaintextBlockStr);
                    plaintextBlockStr = "";
                }

                // Convert number to character
                char c;
                if (num == 26) {
                    c = ' ';
                } else if (num >= 27) {
                    c = (char)(num + 'A' - 27);
                } else {
                    c = (char)(num + 'a');
                }

                decodedBlock.append(c);
            }

            plaintextMessage.append(decodedBlock);
        }


        // Write plaintext message to file
        try {
            FileWriter fileWriter = new FileWriter("test.dec");
            PrintWriter printWriter = new PrintWriter(fileWriter);
            printWriter.print(plaintextMessage);
            printWriter.close();
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        System.out.println("Successfully decrypted message to file.");
    }
}
