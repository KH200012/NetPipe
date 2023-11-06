import jdk.net.Sockets;

import java.net.*;
import java.io.*;
import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.sql.SQLOutput;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import java.net.ServerSocket;
import java.io.IOException;

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;

    HandshakeMessage clientHelloMessage;

    private HandshakeCertificate clientCertificate;

    private String clientCertificateString;

    HandshakeMessage sessionMessage;

    public byte[] sessionKeyBytes;

    public byte[] sessionIV;

    public SessionKey sessionKey;

    HandshakeMessage serverHelloMessage;

    public SessionCipher sessionEncrypter;

    public SessionCipher sessionDecrypter;

    Cipher cipher;



    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "filename");
        arguments.setArgumentSpec("cacert", "filename");
        arguments.setArgumentSpec("key", "filename");

        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }










    public void ClientHello(Socket socket, String caPath) throws Exception {


        clientHelloMessage = HandshakeMessage.recv(socket);
        System.out.println("receive clienthello");

        if(clientHelloMessage.getType().getCode() == 1){

            clientCertificateString = clientHelloMessage.getParameter("Certificate");
            //System.out.println(clientCertificateString);
            byte[] certificateByte = Base64.getDecoder().decode(clientCertificateString);
            clientCertificate = new HandshakeCertificate(certificateByte);
            FileInputStream instream = new FileInputStream(caPath);
            HandshakeCertificate caCertificate = new HandshakeCertificate(instream);
            caCertificate.verify(caCertificate);
            clientCertificate.verify(caCertificate);

        }
        else{
            throw new Exception();
        }
    }


    public HandshakeMessage ServerHello(Socket socket, String certificatepath) throws CertificateException, IOException {

        serverHelloMessage = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        FileInputStream instream = new FileInputStream(certificatepath);
        X509Certificate serverCertificate = new HandshakeCertificate(instream).getCertificate();
        String serverCertificateString = Base64.getEncoder().encodeToString(serverCertificate.getEncoded());
        serverHelloMessage.putParameter("Certificate", serverCertificateString);
        serverHelloMessage.send(socket);
        System.out.println("send severhello");

        return serverHelloMessage;

    }


    public void Session(Socket socket, String privateKeyFile) throws Exception {

        sessionMessage = HandshakeMessage.recv(socket);
        System.out.println("receive session");

        if(sessionMessage.getType().getCode() == 3){

            FileInputStream instream = new FileInputStream(privateKeyFile);
            byte[] privateKeyBytes = instream.readAllBytes();
            HandshakeCrypto serverSession = new HandshakeCrypto(privateKeyBytes);
            sessionKeyBytes = serverSession.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionKey")));
            sessionKey =  new SessionKey(sessionKeyBytes);

            sessionIV = serverSession.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionIV")));




            Cipher cipher= Cipher.getInstance("AES/CTR/NoPadding");


            sessionEncrypter = new SessionCipher(sessionKey, sessionIV, 1);
            sessionDecrypter = new SessionCipher(sessionKey, sessionIV, 0);

        }
        else {
            throw new Exception();
        }
    }


    public void ClientFinish(Socket socket) throws Exception {

        HandshakeMessage clientFinishMessage = HandshakeMessage.recv(socket);
        System.out.println("receive client finish");
        if(clientFinishMessage.getType().getCode() == 4){
            HandshakeCrypto clientFinish = new HandshakeCrypto(clientCertificate);
            byte[] clientDigest = clientFinish.decrypt((Base64.getDecoder().decode(clientFinishMessage.getParameter("Signature"))));

            byte[] timeBytes =  clientFinish.decrypt((Base64.getDecoder().decode(clientFinishMessage.getParameter("TimeStamp"))));
            HandshakeDigest clientDigestCheck = new HandshakeDigest();
            clientDigestCheck.update(clientHelloMessage.getBytes());
            clientDigestCheck.update(sessionMessage.getBytes());
            clientDigestCheck.digest();




            if(Arrays.equals(clientDigestCheck.digest,clientDigest)) {
                System.out.println("Digest is ok!");
            }else{
                throw new Exception();
            }
            String timeStampReceived = new String(timeBytes,"UTF-8");
            int timeStampReceivedlast = Integer.parseInt(timeStampReceived.substring(timeStampReceived.length()-1));

            String time = NetPipeClient.GetTime();
            int timeLast = Integer.parseInt(time.substring(time.length()-1));

            if (timeStampReceivedlast-2 < timeLast && timeStampReceivedlast+2 >timeLast){
                if(!timeStampReceived.substring(0, timeStampReceived.length() - 2).equals(time.substring(0, time.length() - 2))){
                    System.out.println("Timestamp is not ok!");
                }else{
                    System.out.println("Timestamps is ok!");
                }

            }else{throw new Exception(" Timestamp failed");}
        }
        else{
            throw new Exception();
        }
    }


    public void ServerFinish(Socket socket, String privateKeyFile) throws NoSuchAlgorithmException, IOException, CertificateException, InvalidKeySpecException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException {

        HandshakeMessage serverFinishMessage = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        HandshakeDigest serverDigest = new HandshakeDigest();
        serverDigest.update(serverHelloMessage.getBytes());
        serverDigest.digest();


        FileInputStream instream = new FileInputStream(privateKeyFile);
        byte[] privateKeyBytes = instream.readAllBytes();
        HandshakeCrypto serverFinish = new HandshakeCrypto(privateKeyBytes);
        byte[] digestEncrypted = serverFinish.encrypt(serverDigest.digest);
        String time = NetPipeClient.GetTime();
        byte[] timeBytes = time.getBytes(StandardCharsets.UTF_8);
        byte[] timeBytesEncrypted = serverFinish.encrypt(timeBytes);
        serverFinishMessage.putParameter("Signature", Base64.getEncoder().encodeToString(digestEncrypted));
        serverFinishMessage.putParameter("TimeStamp", Base64.getEncoder().encodeToString(timeBytesEncrypted));
        serverFinishMessage.send(socket);
        System.out.println("send serverfinish");


    }

    public NetPipeServer(Socket socket, String caPath, String userPath, String privateKey) throws Exception {

        ClientHello(socket, caPath);
        ServerHello(socket, userPath);
        Session( socket, privateKey);

        ServerFinish( socket, privateKey);
        ClientFinish(socket);


    }




    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) throws Exception {
        parseArgs(args);
        ServerSocket serverSocket = null;

        int port = Integer.parseInt(arguments.get("port"));
        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.exit(1);
        }


        NetPipeServer aa = new NetPipeServer(socket,arguments.get("cacert"), arguments.get("usercert"), arguments.get("key"));


        try {
            OutputStream socketOutEncry = aa.sessionEncrypter.openEncryptedOutputStream(socket.getOutputStream());
            InputStream  socketInDecry = aa.sessionDecrypter.openDecryptedInputStream(socket.getInputStream());
            Forwarder.forwardStreams(System.in, System.out,aa.sessionDecrypter.openDecryptedInputStream(socket.getInputStream()),aa.sessionEncrypter.openEncryptedOutputStream(socket.getOutputStream()), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
