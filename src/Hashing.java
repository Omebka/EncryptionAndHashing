import java.io.FileInputStream;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Hashing {
    public static String checkSum(String path, String algorithm) throws NoSuchAlgorithmException, IOException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        DigestInputStream dis = new DigestInputStream(new FileInputStream(path), md);
        while (dis.read() != -1) {
            md = dis.getMessageDigest();
        }
        return Base64.getEncoder().encodeToString(md.digest());
    }
}
