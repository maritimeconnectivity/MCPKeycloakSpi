/* Copyright 2016 Danish Maritime Authority.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package net.maritimecloud.identityregistry.keycloak.spi.authenticators.certificate.utils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.jboss.logging.Logger;

/**
 * Simplified version of the CertificateUtil in Maritime Cloud Identity Registry code base
 */
public class CertificateUtil {

    private static final Logger logger = Logger.getLogger(CertificateUtil.class);

    public static final String ROOT_CERT_ALIAS = "rootcert";
    public static final String INTERMEDIATE_CERT_ALIAS = "imcert";
    public static final String BC_PROVIDER_NAME = "BC";
    public static final String KEYSTORE_TYPE = "jks";
    public static final String SIGNER_ALGORITHM = "SHA224withECDSA";

    //@Value("${net.maritimecloud.idreg.certs.root-keystore}")
    private String ROOT_KEYSTORE_PATH;

    //@Value("${net.maritimecloud.idreg.certs.it-keystore}")
    private String INTERMEDIATE_KEYSTORE_PATH;

    //@Value("${net.maritimecloud.idreg.certs.keystore-password}")
    private String KEYSTORE_PASSWORD;

    //@Value("${net.maritimecloud.idreg.certs.truststore}")
    private String TRUSTSTORE_PATH;

    //@Value("${net.maritimecloud.idreg.certs.truststore-password}")
    private String TRUSTSTORE_PASSWORD;

    // OIDs used for the extra info stored in the SubjectAlternativeName extension
    // Generate more random OIDs at http://www.itu.int/en/ITU-T/asn1/Pages/UUID/generate_uuid.aspx
    public static final String MC_OID_FLAGSTATE        = "2.25.323100633285601570573910217875371967771";
    public static final String MC_OID_CALLSIGN         = "2.25.208070283325144527098121348946972755227";
    public static final String MC_OID_IMO_NUMBER       = "2.25.291283622413876360871493815653100799259";
    public static final String MC_OID_MMSI_NUMBER      = "2.25.328433707816814908768060331477217690907";
    // See http://www.shipais.com/doc/Pifaq/1/22/ and https://help.marinetraffic.com/hc/en-us/articles/205579997-What-is-the-significance-of-the-AIS-SHIPTYPE-number-
    public static final String MC_OID_AIS_SHIPTYPE     = "2.25.107857171638679641902842130101018412315";
    public static final String MC_OID_MRN              = "2.25.271477598449775373676560215839310464283";
    public static final String MC_OID_PERMISSIONS      = "2.25.174437629172304915481663724171734402331";
    public static final String MC_OID_PORT_OF_REGISTER = "2.25.285632790821948647314354670918887798603";

    public CertificateUtil(String truststorePath, String truststorePassword) {
        TRUSTSTORE_PATH = truststorePath;
        TRUSTSTORE_PASSWORD = truststorePassword;
    }


    public X509Certificate getCertFromString(String certificateHeader) {
        CertificateFactory certificateFactory;
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            logger.error("Exception while creating CertificateFactory", e);
            return null;
        }

        // nginx forwards the certificate in a header by replacing new lines with whitespaces
        // (2 or more). Also replace tabs, which nginx sometimes sends instead of whitespaces.
        String certificateContent = certificateHeader.replaceAll("\\s{2,}", System.lineSeparator()).replaceAll("\\t+", System.lineSeparator());
        if (certificateContent == null || certificateContent.length() < 10) {
            logger.debug("No certificate content found");
            return null;
        }
        X509Certificate userCertificate = null;
        try {
            userCertificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateContent.getBytes("ISO-8859-11")));
        } catch (CertificateException | UnsupportedEncodingException e) {
            logger.error("Exception while converting certificate extracted from header", e);
            return null;
        }
        logger.debug("Certificate was extracted from the header");
        return userCertificate;
    }

    public Map<String, String> getUserFromCert(X509Certificate userCertificate) {
        Map<String, String> user = new HashMap<>();
        String certDN = userCertificate.getSubjectDN().getName();
        X500Name x500name = new X500Name(certDN);
        String fullname = getElement(x500name, BCStyle.CN);
        user.put("fullname", fullname);
        String combinedOrg = getElement(x500name, BCStyle.O);
        user.put("email", getElement(x500name, BCStyle.EmailAddress));
        // Extract first and last name from full name
        String lastName = "";
        String firstName = "";
        if (fullname.split("\\w+").length>1) {
            lastName = fullname.substring(fullname.lastIndexOf(" ")+1);
            firstName = fullname.substring(0, fullname.lastIndexOf(' '));
        } else {
            firstName = fullname;
        }
        user.put("lastName", lastName);
        user.put("firstName", firstName);
        String[] orgNames = combinedOrg.split(";");
        String orgShortName = orgNames[0].toLowerCase();
        user.put("orgShortName", orgShortName);
        user.put("orgFullName", orgNames[1]);
        // prefix orgUserName with org shortname if not already done
        String orgUserName = getElement(x500name, BCStyle.OU).toLowerCase();
        if (!orgUserName.startsWith(orgShortName + ".")) {
            orgUserName = orgShortName.toLowerCase() + "." + orgUserName;
        }

        user.put("orgUnitName", orgUserName);

        /*essence.setUid(name);
        essence.setDn(certDN);
        essence.setCn(new String[] { name });
        essence.setSn(name);
        essence.setO(getElement(x500name, BCStyle.O));
        essence.setOu(getElement(x500name, BCStyle.OU));
        essence.setDescription(certDN);
        // Hack alert! There is no country property in this type, so we misuse PostalAddress...
        essence.setPostalAddress(getElement(x500name, BCStyle.C));*/
        logger.debug("Parsed certificate, name: " + fullname);

        // Extract info from Subject Alternative Name extension
        Collection<List<?>> san = null;
        try {
            san = userCertificate.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            logger.warn("could not extract info from Subject Alternative Names - will be ignored.");
        }
        // Check that the certificate includes the SubjectAltName extension
        if (san != null) {
            // Use the type OtherName to search for the certified server name
            for (List item : san) {
                Integer type = (Integer) item.get(0);
                if (type == 0) {
                    // Type OtherName found so return the associated value
                    ASN1InputStream decoder = null;
                    String oid = "";
                    String value = "";
                    try {
                        // Value is encoded using ASN.1 so decode it to get it out again
                        decoder = new ASN1InputStream((byte[]) item.toArray()[1]);
                        DLSequence seq = (DLSequence) decoder.readObject();
                        ASN1ObjectIdentifier asnOID = (ASN1ObjectIdentifier) seq.getObjectAt(0);
                        ASN1Encodable encoded = seq.getObjectAt(1);
                        encoded = ((DERTaggedObject) encoded).getObject();
                        encoded = ((DERTaggedObject) encoded).getObject();
                        oid = asnOID.getId();
                        value = ((DERUTF8String) encoded).getString();
                    } catch (UnsupportedEncodingException e) {
                        logger.error("Error decoding subjectAltName" + e.getLocalizedMessage(),e);
                        continue;
                    } catch (Exception e) {
                        logger.error("Error decoding subjectAltName" + e.getLocalizedMessage(),e);
                        continue;
                    } finally {
                        if (decoder != null) {
                            try {
                                decoder.close();
                            } catch (IOException e) {
                            }
                        }
                    }
                    logger.debug("oid: " + oid + ", value: " + value);
                    switch (oid) {
                        case MC_OID_FLAGSTATE:
                        case MC_OID_CALLSIGN:
                        case MC_OID_IMO_NUMBER:
                        case MC_OID_MMSI_NUMBER:
                        case MC_OID_AIS_SHIPTYPE:
                        case MC_OID_PORT_OF_REGISTER:
                            logger.debug("Ship specific OIDs are ignored");
                            break;
                        case MC_OID_MRN:
                            // We only support 1 mrn
                            user.put("mrn", value);
                            break;
                        case MC_OID_PERMISSIONS:
                            user.put("permissions", value);
                            break;
                        default:
                            logger.error("Unknown OID!");
                            break;
                    }
                } else {
                    // Other types are not supported so ignore them
                    logger.warn("SubjectAltName of invalid type found: " + type);
                }
            }
        }
        return user;
    }

    private Certificate getRootCertificate() {
        logger.debug(TRUSTSTORE_PATH);
        FileInputStream is;
        try {
            is = new FileInputStream(TRUSTSTORE_PATH);
        } catch (FileNotFoundException e) {
            logger.error("Could not open truststore", e);
            return null;
        }
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            keystore.load(is, TRUSTSTORE_PASSWORD.toCharArray());
            //KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(TRUSTSTORE_PASSWORD.toCharArray());
            Certificate rootCert = keystore.getCertificate(ROOT_CERT_ALIAS);
            return rootCert;

        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
            logger.error("Could not load root certificate", e);
            return null;
        }

    }

    public boolean verifyCertificate(X509Certificate certToVerify) {
        Certificate rootCert = getRootCertificate();
        JcaX509CertificateHolder certHolder;
        try {
            certHolder = new JcaX509CertificateHolder(certToVerify);
        } catch (CertificateEncodingException e) {
            logger.error("Could not create JcaX509CertificateHolder", e);
            return false;
        }
        PublicKey pubKey = rootCert.getPublicKey();
        if (pubKey == null) {
            return false;
        }
        ContentVerifierProvider contentVerifierProvider = null;
        try {
            contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider(BC_PROVIDER_NAME).build(pubKey);
        } catch (OperatorCreationException e) {
            logger.error("Could not create ContentVerifierProvider from public key", e);
            return false;
        }
        if (contentVerifierProvider == null) {
            return false;
        }
        try {
            if (certHolder.isSignatureValid(contentVerifierProvider)) {
                return true;
            }
        } catch (CertException e) {
            logger.error("Error when trying to validate signature", e);
            return false;
        }
        return true;
    }

    /**
     * Extract a value from the DN extracted from a certificate
     *
     * @param x500name
     * @param style
     * @return
     */
    public static String getElement(X500Name x500name, ASN1ObjectIdentifier style) {
        RDN cn = x500name.getRDNs(style)[0];
        return valueToString(cn.getFirst().getValue());
    }

    /**
     * Simplified version of IETFUtils.valueToString where some "special" chars was escaped
     * @param value
     * @return
     */
    public static String valueToString(ASN1Encodable value)
    {
        StringBuffer vBuf = new StringBuffer();
        if (value instanceof ASN1String && !(value instanceof DERUniversalString)) {
            String v = ((ASN1String)value).getString();
            vBuf.append(v);
        } else {
            try {
                vBuf.append("#" + bytesToString(Hex.encode(value.toASN1Primitive().getEncoded(ASN1Encoding.DER))));
            } catch (IOException e) {
                throw new IllegalArgumentException("Other value has no encoded form");
            }
        }
        logger.debug(vBuf.toString());
        return vBuf.toString().trim();
    }

    private static String bytesToString(byte[] data) {
        char[]  cs = new char[data.length];
        for (int i = 0; i != cs.length; i++) {
            cs[i] = (char)(data[i] & 0xff);
        }
        return new String(cs);
    }
}
