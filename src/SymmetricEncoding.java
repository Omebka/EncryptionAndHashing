import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;

public class SymmetricEncoding {
    public static void main(String[] args) {
        try {
            // 1. Шифруем.
            // Читаем файл по данному пути
            SymmetricEncoding symmetricEncoding = new SymmetricEncoding("Files for symmetric encoding/Image/hp.jpg");

            // Создаем ключ для шифрования
            SecretKey key = SymmetricEncoding.createSecretKey("AES");

            // Конвертируем ключ в читабельный формат и записываем его в txt-файл
            Files.writeString(Paths.get("Files for symmetric encoding/Image/key.txt"), SymmetricEncoding.convertSecretKeyToString(key));

            // Шифруем информацию и кладем ее в txt-файл
            byte[] encryptedInfo = SymmetricEncoding.encrypt("AES/ECB/PKCS5Padding", key, symmetricEncoding.getBytes());
            Files.write(Paths.get("Files for symmetric encoding/Image/encrypted hp.txt"), Base64.getEncoder().encode(encryptedInfo));

            // 2. Расшифровываем.
            // Читаем зашифрованную информацию и ключ из файлов выше, конвертируем ключ в формат SecretKey
            SymmetricEncoding symmetricDecoding = new SymmetricEncoding("Files for symmetric encoding/Image/encrypted hp.txt");
            String keyString = Files.readString(Paths.get("Files for symmetric encoding/Image/key.txt"));
            SecretKey key1 = SymmetricEncoding.convertStringToSecretKey(keyString, "AES");

            // Расшифровываем информацию и записываем ее в файл
            byte[] decryptedInfo = SymmetricEncoding.decrypt("AES/ECB/PKCS5Padding", key1, symmetricDecoding.getBytes());
            SymmetricEncoding.createFileFromByteArray("Files for symmetric encoding/Image/decrypted hp.jpg", decryptedInfo);

            // 3. Проверим хеши.
            // Получим хеш оригинального файла
            String hashOfOriginal = Hashing.checkSum("Files for symmetric encoding/Image/hp.jpg", "SHA-256");
            System.out.println("Хеш оригинала:\n" + hashOfOriginal);

            // Получим хэш расшифрованного файла
            String hashOfDecrypted = Hashing.checkSum("Files for symmetric encoding/Image/decrypted hp.jpg", "SHA-256");
            System.out.println("Хеш расшифрованного:\n" + hashOfDecrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private final byte[] bytes;

    public SymmetricEncoding(String path) throws IOException {
        bytes = Files.readAllBytes(Paths.get(path));
    }

    public byte[] getBytes() {
        return bytes;
    }

    public static byte[] encrypt(String algorithm, SecretKey key, byte[] bytes) throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(bytes);
    }

    public static byte[] decrypt(String algorithm, SecretKey key, byte[] encryptedInfo) throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(Base64.getDecoder().decode(encryptedInfo));
    }

    public static SecretKey createSecretKey(String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(algorithm);
        keygen.init(256);
        return keygen.generateKey();
    }

    public static String convertSecretKeyToString(SecretKey key) {
        byte[] rawData = key.getEncoded();
        return Base64.getEncoder().encodeToString(rawData);
    }

    public static SecretKey convertStringToSecretKey(String key, String algorithm) {
        byte[] decodedKey = Base64.getDecoder().decode(key);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, algorithm);
    }

    public static void createFileFromByteArray(String path, byte[] bytes) throws IOException {
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(bytes);
        fos.close();
    }
}
