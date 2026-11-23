import javax.crypto.Cipher;

public class Cryptor {
    public static Cipher getCipher() throws Exception {
        return Cipher.getInstance("DES");
    }
}
