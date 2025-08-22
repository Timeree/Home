import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

public class Core {
    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 128; // MD5生成128位密钥（AES-128）
    private static final int IV_LENGTH = 16;

    public static void main(String[] args) {
        if (args.length < 1) {
            System.exit(1);
        }

        String password = args[0] + "123456789";
        boolean isUpdate = args.length >= 2 && (args[1].equals("-u") || args[1].equals("--update"));

        try {
            if (isUpdate) {
                File coreFile = new File("core");
                if (!coreFile.exists()) {
                    System.err.println("No core found");
                    System.exit(1);
                }

                byte[] coreData = readFile(coreFile);
                byte[] encryptedData = encrypt(coreData, password);
                writeFile(new File("password"), encryptedData);
                System.out.println("core > password");

                Process pushProcess = new ProcessBuilder("./push").start();
                int exitCode = pushProcess.waitFor();
                if (exitCode != 0) {
                    System.err.println("push failed: " + exitCode);
                    System.exit(exitCode);
                }

            } else {
                File passwordFile = new File("password");
                if (!passwordFile.exists()) {
                    System.err.println("No password found");
                    System.exit(1);
                }

                byte[] encryptedData = readFile(passwordFile);
                byte[] decryptedData = decrypt(encryptedData, password);
                System.out.println(new String(decryptedData, StandardCharsets.UTF_8));
            }

        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }

    // 使用MD5从密码生成密钥（128位）
    private static SecretKeySpec getSecretKey(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] keyBytes = md.digest(password.getBytes(StandardCharsets.UTF_8));
        // MD5生成16字节（128位），正好符合AES-128密钥长度
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static byte[] encrypt(byte[] data, String password) throws Exception {
        SecretKeySpec key = getSecretKey(password);
        Cipher cipher = Cipher.getInstance(ALGORITHM);

        // 生成随机IV
        byte[] iv = new byte[IV_LENGTH];
        new java.security.SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(data);

        // 拼接IV和密文（前16字节为IV）
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        return result;
    }

    private static byte[] decrypt(byte[] encryptedData, String password) throws Exception {
        if (encryptedData.length < IV_LENGTH) {
            throw new IllegalArgumentException("Invalid encrypted data");
        }

        byte[] iv = Arrays.copyOfRange(encryptedData, 0, IV_LENGTH);
        byte[] cipherText = Arrays.copyOfRange(encryptedData, IV_LENGTH, encryptedData.length);

        SecretKeySpec key = getSecretKey(password);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        return cipher.doFinal(cipherText);
    }

    private static byte[] readFile(File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }
            return baos.toByteArray();
        }
    }

    private static void writeFile(File file, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
        }
    }
}
