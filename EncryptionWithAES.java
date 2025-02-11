import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.CipherInputStream;
import java.util.Base64;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class AESCrypto {

    // Method to generate AES secret key
    public static SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); // AES-128
        return keyGenerator.generateKey();
    }

    // Method to encrypt a string using AES
    public static String encrypt(String plainText, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv); // Generate random IV
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());
        
        // Combine IV and encrypted data (IV is required for decryption)
        byte[] ivAndCipherText = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, ivAndCipherText, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, ivAndCipherText, iv.length, encryptedBytes.length);
        
        // Return the Base64 encoded result
        return Base64.getEncoder().encodeToString(ivAndCipherText);
    }

    // Method to decrypt a string using AES
    public static String decrypt(String cipherTextBase64, SecretKey key) throws Exception {
        byte[] cipherTextWithIv = Base64.getDecoder().decode(cipherTextBase64);
        
        byte[] iv = new byte[16];
        System.arraycopy(cipherTextWithIv, 0, iv, 0, iv.length);
        
        byte[] cipherText = new byte[cipherTextWithIv.length - iv.length];
        System.arraycopy(cipherTextWithIv, iv.length, cipherText, 0, cipherText.length);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] decryptedBytes = cipher.doFinal(cipherText);
        
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            // Generate AES secret key
            SecretKey secretKey = generateSecretKey();

            // Sample plain text message
            String plainText = "Hello, this is a secret message!";
            System.out.println("Original Message: " + plainText);

            // Encrypt the message
            String encryptedMessage = encrypt(plainText, secretKey);
            System.out.println("Encrypted Message (Base64): " + encryptedMessage);

            // Decrypt the message
            String decryptedMessage = decrypt(encryptedMessage, secretKey);
            System.out.println("Decrypted Message: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
