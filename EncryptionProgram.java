
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionProgram {

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("Encryption Program");
            System.out.println("------------------");
            System.out.println("1. AES");
            System.out.println("2. 3DES");
            System.out.println("3. OTP");

            System.out.print("Choose an encryption algorithm (1 OR 2 OR 3): ");
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline character

            switch (choice) {
                case 1:
                    aesOptions(scanner);
                    break;
                case 2:
                    des3Options(scanner);
                    break;
                case 3:
                    otpOptions(scanner);
                    break;
                default:
                    System.out.println("Invalid choice. Exiting program.");
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void aesOptions(Scanner scanner) {
        System.out.println("AES Encryption/Decryption Program");
        System.out.println("---------------------------------");
        System.out.println("1. Encrypt");
        System.out.println("2. Decrypt");
        System.out.print("Enter your choice (1 or 2): ");
        int choice = scanner.nextInt();
        scanner.nextLine();

    

        if (choice == 1) {
            System.out.print("Enter the plain message: ");
            String plainMessage = scanner.nextLine();
            System.out.print("Enter the encryption key (16, 24, or 32 characters): ");
            String encryptionKey = scanner.nextLine();
            if (encryptionKey.length()==16|| encryptionKey.length()==24|| encryptionKey.length()==32){
              String encryptedText = aesEncrypt(plainMessage, encryptionKey);
              System.out.println("Encrypted Text: " + encryptedText);
            }
            else{
                System.out.println("yuor key length wrong");
            }


            
        } else if (choice == 2) {
            System.out.print("Enter the encrypted text: ");
            String encryptedText = scanner.nextLine();
            System.out.print("Enter the decryption key (16, 24, or 32 characters): ");
            String decryptionKey = scanner.nextLine();

            String decryptedMessage = aesDecrypt(encryptedText, decryptionKey);
            System.out.println("Decrypted Message: " + decryptedMessage);
        } else {
            System.out.println("Invalid choice. Please enter 1 or 2.");
        }
    }

    private static void otpOptions(Scanner scanner) {
        System.out.println("3DES Encryption/Decryption Program");
        System.out.println("----------------------------------");
        System.out.println("1. Encrypt");
        System.out.println("2. Decrypt");
        System.out.print("Enter your choice (1 or 2): ");
        int choice = scanner.nextInt();
        scanner.nextLine();
        if (choice == 1) {
        System.out.print("Enter the plain message: ");
        String plainMessage = scanner.nextLine();
        
        System.out.print("Enter the encryption key equal or greater than plain text ");
        String encryptionKey = scanner.nextLine();
        if (plainMessage.length() > encryptionKey.length()) {
            System.out.println("Error: The length of the message must less than or equal to the key length.");
        }
        else{
            String encryptedText = otpEncrypt(plainMessage, encryptionKey);
            System.out.println("Encrypted Text: " + encryptedText);
        }


        
    } else if (choice == 2) {
        System.out.print("Enter the encrypted text: ");
        String encryptedText = scanner.nextLine();
        System.out.print("Enter the decryption key: ");
        String decryptionKey = scanner.nextLine();

        String decryptedMessage = otpDecrypt(encryptedText, decryptionKey);
        System.out.println("Decrypted Message: " + decryptedMessage);
    } else {
        System.out.println("Invalid choice. Please enter 1 or 2 or 3.");
    }
}


    private static void des3Options(Scanner scanner) {
        System.out.println("3DES Encryption/Decryption Program");
        System.out.println("----------------------------------");
        System.out.println("1. Encrypt");
        System.out.println("2. Decrypt");
        System.out.print("Enter your choice (1 or 2): ");
        int choice = scanner.nextInt();
        scanner.nextLine();

        if (choice == 1) {
            System.out.print("Enter the plain message: ");
            String plainMessage = scanner.nextLine();
            System.out.print("Enter the first encryption key (24 characters): ");
            String encryptionKeyone = scanner.nextLine();
            System.out.print("Enter the second encryption key (24 characters): ");
            String encryptionKeytwo = scanner.nextLine();
            System.out.print("Enter the third encryption key (24 characters): ");
            String encryptionKeythree = scanner.nextLine();
            if (encryptionKeyone.length()==24 && encryptionKeytwo.length() ==24 && encryptionKeythree.length() ==24){
                String encryptedText1 = des3Encrypt(plainMessage, encryptionKeyone);
                System.out.println("Encrypted Text: " + encryptedText1);
                String encryptedText2 = des3Encrypt(plainMessage, encryptionKeytwo);
                System.out.println("Encrypted Text: " + encryptedText2);
                String encryptedText3 = des3Encrypt(plainMessage, encryptionKeythree);
                System.out.println("Encrypted Text: " + encryptedText3);
              }
              else{
                  System.out.println("yuor key length wrong");
              }
            
        } else if (choice == 2) {
            System.out.print("Enter the encrypted text: ");
            String encryptedText = scanner.nextLine();
            
            System.out.print("Enter the third encryption key (24 characters): ");
            String decryptionKeythree = scanner.nextLine();
            System.out.print("Enter the second encryption key (24 characters): ");
            String decryptionKeytwo = scanner.nextLine();
            System.out.print("Enter the first decryption key (24 characters): ");
            String decryptionKeyone = scanner.nextLine();

            String decryptedMessage = des3Decrypt(encryptedText, decryptionKeythree);
            System.out.println("Decrypted Message1: " + decryptedMessage);
            String decryptedMessage2 = des3Decrypt(encryptedText, decryptionKeytwo);
            System.out.println("Decrypted Message2: " + decryptedMessage2);
            String decryptedMessage3 = des3Decrypt(encryptedText, decryptionKeyone);
            System.out.println("Decrypted Message i.e Plain Text is: " + decryptedMessage3);
        } else {
            System.out.println("Invalid choice. Please enter 1 or 2.");
        }
    }

    public static String aesEncrypt(String plainText, String encryptionKey) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);

            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static String aesDecrypt(String encryptedText, String decryptionKey) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(decryptionKey.getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);

            byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }


    public static String des3Encrypt(String plainText, String encryptionKey) {
        try {
            byte[] keyBytes = encryptionKey.getBytes(StandardCharsets.UTF_8);
            DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey secretKey = keyFactory.generateSecret(keySpec);

            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static String des3Decrypt(String encryptedText, String decryptionKey) {
        try {
            byte[] keyBytes = decryptionKey.getBytes(StandardCharsets.UTF_8);
            DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey secretKey = keyFactory.generateSecret(keySpec);

            Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private static String otpEncrypt(String plainMessage, String encryptionKey) {
        StringBuilder encryptedText = new StringBuilder();
        for (int i = 0; i < plainMessage.length(); i++) {
            char plainChar = plainMessage.charAt(i);
            char keyChar = encryptionKey.charAt(i % encryptionKey.length());
            char encryptedChar = (char) (plainChar ^ keyChar);
            encryptedText.append(encryptedChar);
        }
        return encryptedText.toString();
    }

    private static String otpDecrypt(String encryptedText, String decryptionKey) {
        return otpEncrypt(encryptedText, decryptionKey); // XOR operation is its own inverse
    }
}


