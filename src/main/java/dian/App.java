package dian;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

public class App {
    public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
            IOException, UnrecoverableKeyException, InvalidAlgorithmParameterException, MarshalException,
            XMLSignatureException, SAXException, ParserConfigurationException {
        final InputStream xmlInputStream = App.class.getClassLoader().getResourceAsStream("GetStatus.xml");
        final InputStream p12InputStream = App.class.getClassLoader().getResourceAsStream("keystore.p12");
        final String password = "";

        DianSign dianSign = new DianSign().withDocument(xmlInputStream).withKeyStore(p12InputStream, password);
        dianSign.sign();
        System.out.println(Utils.toString(dianSign.getDocument())
        );
        // String url = "https://vpfe-hab.dian.gov.co/WcfDianCustomerServices.svc";
        // URL obj = new URL(url);
        // HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
        // con.setRequestMethod("POST");
        // con.setRequestProperty("Content-Type", "application/soap+xml");
        // con.setDoOutput(true);
        // DataOutputStream wr = new DataOutputStream(con.getOutputStream());
        // wr.writeBytes(Utils.toString(dianSign.getDocument()));;
        // wr.flush();
        // wr.close();
        // String responseStatus = con.getResponseMessage();
        // System.out.println(responseStatus);
    }

}