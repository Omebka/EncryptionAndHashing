import javax.crypto.*;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class AsymmetricEncoding {
    public static void main(String[] args) {
        try {
            // 1. Шифруем файл симметричным методом.
            // Читаем файл по данному пути
            SymmetricEncoding symmetricEncoding = new SymmetricEncoding("Files for asymmetric encoding/Exe/generator.exe");

            // Шифруем информацию с помощью симметричного шифрования
            SecretKey symmetricKey = SymmetricEncoding.createSecretKey("AES");
            Files.writeString(Paths.get("Files for asymmetric encoding/Exe/symmetric key.txt"), SymmetricEncoding.convertSecretKeyToString(symmetricKey));
            byte[] symmetricallyEncodedInfo = SymmetricEncoding.encrypt("AES/ECB/PKCS5Padding", symmetricKey, symmetricEncoding.getBytes());
            Files.write(Paths.get("Files for asymmetric encoding/Exe/symmetrically encoded generator.txt"), Base64.getEncoder().encode(symmetricallyEncodedInfo));

            // 2. Шифруем ключ, которым происходило симметричное шифрования, с помощью асимметричных методов.
            // Читаем файл-ключ по данному пути
            AsymmetricEncoding asymmetricEncodingSymmetricKey = new AsymmetricEncoding("Files for asymmetric encoding/Exe/symmetric key.txt");

            // Создаем пару ключей для шифрования
            KeyPair keyPair = AsymmetricEncoding.createKeyPair("RSA");

            // Конвертируем ключи в читабельный формат и записываем их в txt-файлы
            Files.writeString(Paths.get("Files for asymmetric encoding/Exe/public key.txt"), AsymmetricEncoding.convertKeyToString(keyPair.getPublic()));
            Files.writeString(Paths.get("Files for asymmetric encoding/Exe/private key.txt"), AsymmetricEncoding.convertKeyToString(keyPair.getPrivate()));

            // Шифруем симметричный ключ асимметричным методом публичным ключом и кладем его в txt-файл
            byte[] encodedSymmetricKey = AsymmetricEncoding.encrypt("RSA", keyPair.getPublic(), asymmetricEncodingSymmetricKey.getBytes());
            Files.write(Paths.get("Files for asymmetric encoding/Exe/encoded symmetric key.txt"), Base64.getEncoder().encode(encodedSymmetricKey));

            // 3. Расшифровываем симметричный ключ, которым был зашифрован оригинальный файл.
            // Читаем зашифрованный симметричный ключ и приватный ключ из файлов выше, конвертируем приватный ключ в формат PrivateKey
            AsymmetricEncoding asymmetricDecodingSymmetricKey = new AsymmetricEncoding("Files for asymmetric encoding/Exe/encoded symmetric key.txt");
            String privateKeyString = Files.readString(Paths.get("Files for asymmetric encoding/Exe/private key.txt"));
            PrivateKey privateKey = AsymmetricEncoding.convertStringToPrivateKey(privateKeyString, "RSA");

            // Расшифровываем симметричный ключ приватным ключом и записываем его в txt-файл
            byte[] decodedSymmetricKeyBytes = AsymmetricEncoding.decrypt("RSA", privateKey, asymmetricDecodingSymmetricKey.getBytes());
            Files.write(Paths.get("Files for asymmetric encoding/Exe/decoded symmetric key.txt"), decodedSymmetricKeyBytes);

            // 4. Расшифровываем симметрично-зашифрованную информацию и записываем ее в файл.
            // Читаем расшифрованный симметричный ключ и конвертируем его в формат SecretKey
            SymmetricEncoding readDecodedSymmetricKeyBytes = new SymmetricEncoding("Files for asymmetric encoding/Exe/decoded symmetric key.txt");
            SecretKey decodedSymmetricKey = SymmetricEncoding.convertStringToSecretKey(new String(readDecodedSymmetricKeyBytes.getBytes()), "AES");

            // Расшифровываем симметрично-зашифрованную информацию и записываем ее в файл
            SymmetricEncoding encodedInfo = new SymmetricEncoding("Files for asymmetric encoding/Exe/symmetrically encoded generator.txt");
            byte[] decodedInfo = SymmetricEncoding.decrypt("AES/ECB/PKCS5Padding", decodedSymmetricKey, encodedInfo.getBytes());
            AsymmetricEncoding.createFileFromByteArray("Files for asymmetric encoding/Exe/decoded generator.exe", decodedInfo);

            // 5. Проверим хеши.
            // Получим хеш оригинального файла
            String hashOfOriginal = Hashing.checkSum("Files for asymmetric encoding/Exe/generator.exe", "SHA-256");
            System.out.println("Хеш оригинала:\n" + hashOfOriginal);

            // Получим хэш расшифрованного файла
            String hashOfDecrypted = Hashing.checkSum("Files for asymmetric encoding/Exe/decoded generator.exe", "SHA-256");
            System.out.println("Хеш расшифрованного:\n" + hashOfDecrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private final byte[] bytes;

    public AsymmetricEncoding(String path) throws IOException {
        bytes = Files.readAllBytes(Paths.get(path));
    }

    public byte[] getBytes() {
        return bytes;
    }

    public static byte[] encrypt(String algorithm, PublicKey publicKey, byte[] bytes) throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidKeyException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(bytes);
    }

    public static byte[] decrypt(String algorithm, PrivateKey privateKey, byte[] encryptedInfo) throws NoSuchPaddingException,
            NoSuchAlgorithmException,
            IllegalBlockSizeException,
            BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(Base64.getDecoder().decode(encryptedInfo));
    }

    public static KeyPair createKeyPair(String algorithm) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(1024);
        return generator.generateKeyPair();
    }

    public static String convertKeyToString(Key key) {
        byte[] rawData = key.getEncoded();
        return Base64.getEncoder().encodeToString(rawData);
    }

    public static PrivateKey convertStringToPrivateKey(String key, String algorithm) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        byte[] decodedKey = Base64.getDecoder().decode(key);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(decodedKey);
        return kf.generatePrivate(keySpecPKCS8);
    }

    public static void createFileFromByteArray(String path, byte[] bytes) throws IOException {
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(bytes);
        fos.flush();
        fos.close();
    }
}
