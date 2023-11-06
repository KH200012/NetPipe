import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HandshakeDigest {

    /*
     * Constructor -- initialise a digest for SHA-256
     */
    public MessageDigest md;

    public byte[] digest;



    public HandshakeDigest() throws NoSuchAlgorithmException {

        this.md = MessageDigest.getInstance("SHA-256");

    }

    /*
     * Update digest with input data
     */
    public void update(byte[] input) {
        this.md.update(input);
    }

    /*
     * Compute final digest
     */
    public byte[] digest() {

        this.digest = this.md.digest();


        return this.digest;
    }
};
