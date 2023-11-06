import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.security.SecureRandom;

/*s
 * Skeleton code for class SessionKey
 */

public class SessionKey {

    /*
     * Constructor to create a secret key of a given length
     */

    public SecretKey keyGen;
    public SessionKey(Integer length) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");

        //Creating a SecureRandom object
        SecureRandom secRandom = new SecureRandom();

        //Initializing the KeyGenerator
        generator.init(length);

        //Creating/Generating a key
         this.keyGen = generator.generateKey();
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
        keyGen = new SecretKeySpec(keybytes, 0, keybytes.length, "AES");
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return keyGen;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
        return keyGen.getEncoded();
    }

    /*public String encodedKey(){
        Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(keyGen.getEncoded());


    }*/
}

