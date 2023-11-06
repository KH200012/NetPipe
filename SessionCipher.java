import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.*;

public class SessionCipher {

    //public SecretKey secretkey;

    //public Cipher cipher;

    //public Cipher cipher1;

    //public SecretKey secretKey1;

    public SessionKey sessionkey ;


    public byte[] IV ;

    Cipher cipher;




    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeyException, InvalidAlgorithmParameterException {

        //KeyGenerator genkey = KeyGenerator.getInstance("AES");

        this.sessionkey = key;

       this.cipher = Cipher.getInstance("AES/CTR/NoPadding");

        this.IV = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();

        cipher.init(Cipher.ENCRYPT_MODE,key.getSecretKey(),new IvParameterSpec(this.IV));

    }



    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes, int a) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {

        this.sessionkey = key;

        this.IV = ivbytes;

        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");

        if(a == 0) {

            cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(), new IvParameterSpec(ivbytes));
        }
        if(a ==1){
            cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), new IvParameterSpec(ivbytes));
        }

    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return sessionkey;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return IV;
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
    CipherOutputStream openEncryptedOutputStream(OutputStream os) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {




        return new CipherOutputStream(os,cipher);
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {





        return new CipherInputStream(inputstream, cipher);
    }
}
