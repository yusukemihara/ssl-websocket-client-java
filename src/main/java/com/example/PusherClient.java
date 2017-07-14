package com.example;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import org.eclipse.jetty.websocket.api.Session;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketClose;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketConnect;
import org.eclipse.jetty.websocket.api.annotations.OnWebSocketMessage;
import org.eclipse.jetty.websocket.api.annotations.WebSocket;
import org.eclipse.jetty.websocket.client.ClientUpgradeRequest;
import org.eclipse.jetty.websocket.client.WebSocketClient;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.bind.DatatypeConverter;
import org.eclipse.jetty.util.ssl.SslContextFactory;

public class PusherClient {

    private final URI pusher;
    private final String auth;
    private final String sessionID;
    private final SslContextFactory sslContextFactory;

    public static void main(String[] args) throws URISyntaxException, IOException, KeyStoreException, FileNotFoundException, NoSuchAlgorithmException, CertificateException {
        /*
        URI pusher = new URI("ws://localhost:19401/ws");
        new PusherClient(pusher, "user", "pass", "sessionID").run();
        */
        String user    = "user";
        String pass    = "pass";
        String ca      = "ca.crt";
        String p12     = "cert.p12";
        String p12pass = "certpass";
        URI uri = new URI("wss://pusher-proxy-test.orca.orcamo.jp/ws");
        new PusherClient(uri, user,pass,"sessionID",ca,p12,p12pass).run();        
    }

    public PusherClient(URI pusher, String user, String password, String sessionID) {
        this.pusher = pusher;
        String auth_in = user + ":" + password;
        this.auth = Base64.getEncoder().encodeToString(auth_in.getBytes());
        this.sessionID = sessionID;
        this.sslContextFactory = null;
    }

    public PusherClient(URI pusher, String user, String password, String sessionID, String caFile, String p12File, String p12Pass) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException {
        this.pusher = pusher;
        String auth_in = user + ":" + password;
        this.auth = Base64.getEncoder().encodeToString(auth_in.getBytes());
        this.sessionID = sessionID;

        sslContextFactory = new SslContextFactory();

        KeyStore ks = KeyStore.getInstance("PKCS12");
        InputStream is = new FileInputStream(p12File);
        ks.load(is, p12Pass.toCharArray());
        sslContextFactory.setKeyStore(ks);
        sslContextFactory.setKeyStorePassword(p12Pass);
        sslContextFactory.setTrustStore(createCAFileTrustKeyStore(caFile));     
    }

    public void run() throws IOException {
        WebSocketClient client;
        if (this.sslContextFactory != null) {
            client = new WebSocketClient(sslContextFactory);
        } else {
            client = new WebSocketClient();
        }

        PusherWebSocket socket = new PusherWebSocket();
        try {
            client.start();
            ClientUpgradeRequest request = new ClientUpgradeRequest();
            request.setHeader("Authorization", "Basic " + this.auth);
            request.setHeader("X-GINBEE-TENANT-ID", "1");
            System.out.println("Connecting to : " + this.pusher);
            client.connect(socket, this.pusher, request);
            Thread.sleep(Long.MAX_VALUE);
        } catch (Throwable t) {
            t.printStackTrace();
        } finally {
            try {
                client.stop();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @WebSocket
    public class PusherWebSocket {

        private final String reqID = UUID.randomUUID().toString();
        private final CountDownLatch closeLatch = new CountDownLatch(1);

        @OnWebSocketConnect
        public void onConnect(Session session) {
            System.out.println("---- onConnect");
            try {
                session.getRemote().sendString("{\"command\":\"subscribe\",\"req.id\":\"" + reqID + "\",\"event\":\"*\"}");
            } catch (IOException ex) {
                Logger.getLogger(PusherClient.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        @OnWebSocketMessage
        public void onMessage(String message) {
            System.out.println("---- onMessage");
            System.out.println(message);
        }

        @OnWebSocketClose
        public void onClose(int statusCode, String reason) {
            System.out.println("---- onClose");
            System.out.println(statusCode);
        }

        public boolean awaitClose(int duration, TimeUnit unit) throws InterruptedException {
            return this.closeLatch.await(duration, unit);
        }
    }

    private static X509Certificate parseCertPem(String pem) throws CertificateException {
        byte[] der = DatatypeConverter.parseBase64Binary(pem);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
    }

    private static String[] splitCertFile(String path) throws FileNotFoundException, IOException {

        byte[] fileContentBytes = Files.readAllBytes(Paths.get(path));
        String str = new String(fileContentBytes, StandardCharsets.UTF_8);

        Pattern pattern = Pattern.compile("-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", Pattern.DOTALL);
        Matcher matcher = pattern.matcher(str);
        List<String> list = new ArrayList<>();
        while (matcher.find()) {
            list.add(matcher.group());
        }
        String[] strs = new String[list.size()];
        for (int i = 0; i < list.size(); i++) {
            String s = list.get(i);
            s = s.replace("-----BEGIN CERTIFICATE-----", "");
            strs[i] = s.replace("-----END CERTIFICATE-----", "");
        }
        return strs;
    }

    public static KeyStore createCAFileTrustKeyStore(String caCertPath) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(null);

        String pemStrs[] = splitCertFile(caCertPath);
        for (String pem : pemStrs) {
            X509Certificate cert = parseCertPem(pem);
            keystore.setCertificateEntry(cert.getSubjectDN().toString(), cert);
        }
        return keystore;
    }
}
