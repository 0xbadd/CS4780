package project2;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Scanner;

public class RSAEncrypt {
    public static void main(String[] args) {
        // Read message into string
        String message = "";
        try {
            Path filename = Path.of(args[0]);
            message = Files.readString(filename);
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
        // Ignore punctuation
        message = message.replaceAll("[^a-zA-Z ]", "");

        // Read public key text
        BigInteger E = BigInteger.ZERO;
        BigInteger N = BigInteger.ZERO;
        try {
            File myObj = new File(args[1]);
            Scanner myReader = new Scanner(myObj);

            String pub_e = myReader.nextLine();
            String pub_n = myReader.nextLine();

            E = new BigInteger(pub_e.split(" ")[2]);
            N = new BigInteger(pub_n.split(" ")[2]);

            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        StringBuilder encryptedMessage = new StringBuilder();
        while (message.length() > 0) {
            // Get next block in message
            String blockStr;
            if (message.length() >= 4) {
                blockStr = message.substring(0, 3);
                message = message.substring(3);
            } else {
                blockStr = message;
                message = "";
            }

            // Encode message block
            StringBuilder encodedBlock = new StringBuilder();
            for (int i = 0; i < blockStr.length(); i++) {
                char c = blockStr.charAt(i);
                int n;
                if (c == ' ') {
                    n = 26;
                } else if (c >= 'a' && c <= 'z') {
                    n = (int)c - (int)'a';
                } else {
                    n = (int)c - (int)'A' + 27;
                }
                if (n < 10) {
                    encodedBlock.append("0").append(n);
                } else {
                    encodedBlock.append(n);
                }
            }
            System.out.println(encodedBlock);
            // Encrypt block
            BigInteger cipherBlock = new BigInteger(encodedBlock.toString()).modPow(E, N);

            encryptedMessage.append(cipherBlock.toString()).append(" ");
        }


        // Write encrypted message to file
        try {
            FileWriter fileWriter = new FileWriter("test.enc");
            PrintWriter printWriter = new PrintWriter(fileWriter);
            printWriter.print(encryptedMessage);
            printWriter.close();
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        System.out.println("Successfully encrypted message to file.");
    }
}
