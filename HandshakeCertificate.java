import java.io.FileInputStream;
import java.io.InputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

import java.security.PublicKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;



/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {


    public X509Certificate cert;

    public byte[] Byte;


    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        this.cert = (X509Certificate) certificateFactory.generateCertificate(instream);

    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
       CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
       InputStream in = new ByteArrayInputStream(certbytes);
       this.cert = (X509Certificate)certificateFactory.generateCertificate(in);
         // xx X509Certificate cert = (X509Certificate)certificateFactory.generateCertificate(in);
         // xx this.Byte = cert.getEncoded();



    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateEncodingException {
        return  this.cert.getEncoded();

    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return this.cert;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     * Exceptions must be specified! No catch-all declarations.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        X509Certificate cacert1 = cacert.getCertificate();
        this.cert.verify(cacert1.getPublicKey());
    }

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        X500Principal principal = this.cert.getSubjectX500Principal();
        try {
            LdapName ldapName = new LdapName(principal.getName());
            for (Rdn rdn : ldapName.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("cn")) {
                    return rdn.getValue().toString();
                }
            }
            return principal.getName();
        } catch (NamingException ex) {
            return principal.getName();
        }




        //return null;
    }

    /*
     * return email address of subject
     */

    public String getEmail() throws CertificateEncodingException {

        X500Principal principal = this.cert.getSubjectX500Principal();
        try {
            LdapName ldapName = new LdapName(principal.toString());
            for (Rdn rdn : ldapName.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("emailaddress")) {
                    return rdn.getValue().toString();
                }
            }
            return principal.toString();
        } catch (NamingException ex) {
            return principal.toString();
        }




    }
}
