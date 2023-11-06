
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;




public class HandshakeCrypto {

	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */
	public X509Certificate cert;
	public PublicKey publickey = null;

	public PrivateKey privatekey = null;



	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {

		this.cert = handshakeCertificate.getCertificate();
		this.publickey =  this.cert.getPublicKey();
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */

	public HandshakeCrypto(byte[] keybytes) throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keybytes);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		this.privatekey = factory.generatePrivate(keySpec);




	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance("RSA");
		if(this.privatekey == null){
			cipher.init(Cipher.DECRYPT_MODE, this.publickey);
		}else {
		cipher.init(Cipher.DECRYPT_MODE, this.privatekey);}
		return cipher.doFinal(ciphertext);
    }

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte [] encrypt(byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance("RSA");
		if(this.publickey == null){
			cipher.init(Cipher.ENCRYPT_MODE, this.privatekey);
		}else{
		cipher.init(Cipher.ENCRYPT_MODE, this.publickey);}
		return cipher.doFinal(plaintext);



    }
}
