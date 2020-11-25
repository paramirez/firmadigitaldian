package dian;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class DianSign {

    private final String C14NEXC = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private Document dom;
    private KeyStore keyStore;
    private String alias;
    private String password;
    private Element to;

    public Document getDocument() {
        return this.dom;
    }

    public DianSign withDocument(InputStream xmlInputStream) {
        this.dom = Utils.newDocumentFromInputStream(xmlInputStream);
        return this;
    }

    public DianSign withKeyStore(InputStream p12InputStream, String password)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        this.keyStore = Utils.loadKeyStore(p12InputStream, password);
        this.password = password;
        Enumeration<String> enumeration = this.keyStore.aliases();
        while (enumeration.hasMoreElements())
            this.alias = enumeration.nextElement();
        return this;
    }

    private Element makeHeader() {
        final NodeList headerNodeList = this.dom.getElementsByTagName("soap:Header");
        Element header = null;
        if (headerNodeList.getLength() > 0)
            header = (Element) headerNodeList.item(0);
        else {
            header = this.dom.createElement("soap:Header");
            final NodeList bodyNodeList = this.dom.getElementsByTagName("soap:Body");
            this.dom.insertBefore(header, bodyNodeList.item(0));
        }

        header.setAttribute("xmlns:wsa", "http://www.w3.org/2005/08/addressing");
        return header;
    }

    private void addTimestamp(Element el) {
        final String DATE_TIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSSX";
        final DateTimeFormatter timeStampFormatter = DateTimeFormatter.ofPattern(DATE_TIME_PATTERN);
        final Element timestamp = this.dom.createElement("wsu:Timestamp");
        timestamp.setAttribute("wsu:Id", Utils.uuid("TS"));
        el.appendChild(timestamp);

        final Element created = this.dom.createElement("wsu:Created");
        created.setTextContent(timeStampFormatter.format(ZonedDateTime.now().toInstant().atZone(ZoneId.of("UTC"))));
        timestamp.appendChild(created);

        final Element expires = this.dom.createElement("wsu:Expires");
        expires.setTextContent(
                timeStampFormatter.format(ZonedDateTime.now().plusSeconds(60000).toInstant().atZone(ZoneId.of("UTC"))));
        timestamp.appendChild(expires);
    }

    private String addBinarySecurityToken(Element el) throws KeyStoreException, CertificateEncodingException {
        Certificate certificate = this.keyStore.getCertificate(this.alias);

        byte[] certByte = certificate.getEncoded();

        final String token = Utils.uuid("X509");
        final Element bst = this.dom.createElement("wsse:BinarySecurityToken");
        el.appendChild(bst);

        bst.setAttribute("EncodingType",
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
        bst.setAttribute("ValueType",
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        bst.setAttribute("wsu:Id", token);

        bst.setTextContent(Base64.getEncoder().encodeToString(certByte));

        return token;
    }

    private Element securityTokenReference(String id) {
        Element securityTokenReference = this.dom.createElement("wsse:SecurityTokenReference");
        securityTokenReference.setAttribute("wsu:Id", Utils.uuid("STR"));
        Element reference = this.dom.createElement("wsse:Reference");
        reference.setAttribute("URI", "#" + id);
        reference.setAttribute("ValueType",
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
        securityTokenReference.appendChild(reference);
        return securityTokenReference;
    }

    private void signXML(Node node, String toId, String token)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, UnrecoverableKeyException,
            KeyStoreException, MarshalException, XMLSignatureException {

        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

        List<String> transformPrefixList = new ArrayList<String>();
        transformPrefixList.add("soap wcf");

        Transform c14NEXCTransform = factory.newTransform(C14NEXC, new ExcC14NParameterSpec(transformPrefixList));

        List<Transform> transforms = Arrays.asList(c14NEXCTransform);

        DigestMethod digestMethod = factory.newDigestMethod(DigestMethod.SHA256, null);
        Reference ref = factory.newReference("#" + toId, digestMethod, transforms, null, null);

        List<String> prefixList = new ArrayList<String>();
        prefixList.add("wsa soap wcf");

        CanonicalizationMethod canonicalizationMethod = factory
                .newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, new ExcC14NParameterSpec(prefixList));

        SignatureMethod signatureMethod = factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null);
        SignedInfo si = factory.newSignedInfo(canonicalizationMethod, signatureMethod, Collections.singletonList(ref));

        KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance();
        DOMStructure domStructure = new DOMStructure(securityTokenReference(token));
        KeyInfo ki = keyInfoFactory.newKeyInfo(Collections.singletonList(domStructure), Utils.uuid("KI"));

        XMLSignature signature = factory.newXMLSignature(si, ki, null, Utils.uuid("SIG"), null);
        PrivateKey privateKey = (PrivateKey) this.keyStore.getKey(this.alias, this.password.toCharArray());
        DOMSignContext signContext = new DOMSignContext(privateKey, node);

        signContext.setDefaultNamespacePrefix("ds");
        signContext.setIdAttributeNS(this.to, null, "wsu:Id");
        signature.sign(signContext);
    }

    public void sign() throws CertificateEncodingException, KeyStoreException, UnrecoverableKeyException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, MarshalException, XMLSignatureException,
            IOException, SAXException, ParserConfigurationException {
        System.out.println(this.dom);
        System.out.println(this.keyStore);
        Element header = makeHeader();

        Element security = this.dom.createElement("wsse:Security");
        security.setAttribute("xmlns:wsse",
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd");
        security.setAttribute("xmlns:wsu",
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
        header.appendChild(security);

        addTimestamp(security);
        String tokenBinary = addBinarySecurityToken(security);
        // <wsa:Action>http://wcf.dian.colombia/IWcfDianCustomerServices/GetStatus</wsa:Action>
        // <wsa:To wsu:Id="id-35FF6257A78787EE2516057777211224"
        // xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">https://vpfe-hab.dian.gov.co/WcfDianCustomerServices.svc</wsa:To>

        Element action = this.dom.createElement("wsa:Action");
        action.setTextContent("http://wcf.dian.colombia/IWcfDianCustomerServices/GetStatus");
        header.appendChild(action);

        String toId = Utils.uuid("id");
        Element to = this.dom.createElement("wsa:To");
        to.setAttribute("wsu:Id", toId);
        to.setAttribute("xmlns:wsu",
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
        to.setTextContent("https://vpfe-hab.dian.gov.co/WcfDianCustomerServices.svc");
        header.appendChild(to);
        this.to = to;

        signXML((Node) security, toId, tokenBinary);
    }

}
