import java.io.*;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.Socket;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    HandshakeMessage clientHelloMessage;

    HandshakeMessage serverHelloMessage;

    private HandshakeCertificate serverCertifcate;

    private String serverCertificateString;

    public byte[] sessionKeyBytes;

    public byte[] sessionIV;

    HandshakeMessage sessionMessage;

    public SessionCipher sessionEncrypter;

    public SessionCipher sessionDecrypter;

    public SessionKey sessionKey;



    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
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
        arguments.setArgumentSpec("host", "hostname");
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



    public HandshakeMessage ClientHello(Socket socket, String certificatepath) {

        try {
            clientHelloMessage = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
            FileInputStream instream = new FileInputStream(certificatepath);
            X509Certificate clientCertificate = new HandshakeCertificate(instream).getCertificate();
            String clientCertificateString = Base64.getEncoder().encodeToString(clientCertificate.getEncoded());
            clientHelloMessage.putParameter("Certificate", clientCertificateString);

            clientHelloMessage.send(socket);
            System.out.println("send clienthello");

        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
            System.out.println("error in hello message");
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("error in hello message");
        }
        return clientHelloMessage;


    }

    public void ServerHello(Socket socket, String caPath) throws Exception {

        serverHelloMessage = HandshakeMessage.recv(socket);
        System.out.println("receive serverhello");
        if(serverHelloMessage.getType().getCode() ==2){
            FileInputStream instream = new FileInputStream(caPath);
            HandshakeCertificate caCertificate = new HandshakeCertificate(instream);
            serverCertificateString = serverHelloMessage.getParameter("Certificate");
            byte[] certificateByte = Base64.getDecoder().decode(serverCertificateString);
            serverCertifcate = new HandshakeCertificate(certificateByte);
            caCertificate.verify(caCertificate);
            serverCertifcate.verify(caCertificate);

        }else {
            throw new Exception();
        }
    }


    public HandshakeMessage Session(Socket socket) throws InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {

        sessionMessage = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        HandshakeCrypto clientSession = new HandshakeCrypto(serverCertifcate);
        sessionKey = new SessionKey(128);

        sessionEncrypter = new SessionCipher(sessionKey);

        sessionIV = sessionEncrypter.getIVBytes();
        sessionKeyBytes = sessionKey.getKeyBytes();
        sessionDecrypter = new SessionCipher(sessionKey, sessionIV, 0);
        byte[] sessionKeyEncrypted =  clientSession.encrypt(sessionKeyBytes);
        byte[] sessionIVEncrypted = clientSession.encrypt(sessionIV);
        sessionMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(sessionKeyEncrypted));
        sessionMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(sessionIVEncrypted));


        sessionMessage.send(socket);
        System.out.println("send clientsession");
        return sessionMessage;

    }

    public HandshakeMessage ClientFinish(Socket socket, String privateKeyFile) throws NoSuchAlgorithmException, IOException, CertificateException, InvalidKeySpecException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException {
        HandshakeMessage clientFinishMessage = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        HandshakeDigest clientDigest = new HandshakeDigest();
        clientDigest.update(clientHelloMessage.getBytes());
        clientDigest.update(sessionMessage.getBytes());
        clientDigest.digest();


        FileInputStream instream = new FileInputStream(privateKeyFile);
        byte[] privateKeyBytes = instream.readAllBytes();
        HandshakeCrypto clientFinish = new HandshakeCrypto(privateKeyBytes);
        byte[] digestEncrypted = clientFinish.encrypt(clientDigest.digest);
        String time = NetPipeClient.GetTime();
        byte[] timeBytes = time.getBytes(StandardCharsets.UTF_8);
        byte[] timeBytesEncrypted = clientFinish.encrypt(timeBytes);
        clientFinishMessage.putParameter("Signature", Base64.getEncoder().encodeToString(digestEncrypted));
        clientFinishMessage.putParameter("TimeStamp", Base64.getEncoder().encodeToString(timeBytesEncrypted));


        clientFinishMessage.send(socket);
        System.out.println("send clientfinish");
        return clientFinishMessage;

    }


    public void ServerFinish(Socket socket) throws Exception {

        HandshakeMessage serverFinishMessage = HandshakeMessage.recv(socket);
        System.out.println("receive serverfinish");
        if (serverFinishMessage.getType().getCode() !=5 ){
            throw new Exception();
        }
        HandshakeCrypto serverFinish = new HandshakeCrypto(serverCertifcate);
        byte[] serverDigest = serverFinish.decrypt((Base64.getDecoder().decode(serverFinishMessage.getParameter("Signature"))));
        byte[] timeBytes =  serverFinish.decrypt((Base64.getDecoder().decode(serverFinishMessage.getParameter("TimeStamp"))));




        HandshakeDigest serverDigestCheck = new HandshakeDigest();
        serverDigestCheck.update(serverHelloMessage.getBytes());
        serverDigestCheck.digest();




        if(Arrays.equals(serverDigestCheck.digest,serverDigest)) {
            System.out.println("Digest is ok!");
        }else {throw new Exception();}

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

        }else{throw new Exception("Timestamp  failed");}
    }

    public NetPipeClient(Socket socket, String caPath, String userPath, String privateKey) throws Exception {

        ClientHello(socket, userPath);
        ServerHello(socket, caPath);
        Session( socket);
        ServerFinish( socket);
        ClientFinish(socket, privateKey);


    }







    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) throws Exception {
        Socket socket = null;

        parseArgs(args);
        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }

        NetPipeClient aa = new NetPipeClient(socket,arguments.get("cacert"), arguments.get("usercert"), arguments.get("key"));

        try {

            OutputStream socketOutEncry = aa.sessionEncrypter.openEncryptedOutputStream(socket.getOutputStream());
            InputStream  socketInDecry = aa.sessionDecrypter.openDecryptedInputStream(socket.getInputStream());
            Forwarder.forwardStreams(System.in, System.out,aa.sessionDecrypter.openDecryptedInputStream(socket.getInputStream()),aa.sessionEncrypter.openEncryptedOutputStream(socket.getOutputStream()), socket);





        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);}
         catch (Exception e) {
            throw new RuntimeException(e);
        }

    }




    public static String GetTime() throws IOException {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String dateString=null;
        try {
            Calendar calendar = Calendar.getInstance();
            Date date = calendar.getTime();
            dateString = simpleDateFormat.format(date);
            return dateString;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dateString;

    }
}
